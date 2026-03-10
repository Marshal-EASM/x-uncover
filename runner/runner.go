package runner

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/uncover"
	"github.com/projectdiscovery/uncover/sources"
	errorutil "github.com/projectdiscovery/utils/errors"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// Runner is an instance of the uncover enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options      *Options
	service      *uncover.Service
	outputWriter *OutputWriter
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists
// and setting up loggers, etc.
func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{options: options}
	if len(options.InputIP) > 0 {
		runner.ParseIPQuery()
	} else {
		appendAllQueries(options)
	}

	opts := uncover.Options{
		Agents:     options.Engine,
		Queries:    options.Query,
		Limit:      options.Limit,
		NewQueries: options.NewQuery,
	}

	service, err := uncover.New(&opts)
	if err != nil {
		return nil, err
	}
	runner.service = service

	runner.outputWriter, err = NewOutputWriter()
	if err != nil {
		return nil, err
	}

	if !options.Verbose {
		runner.outputWriter.AddWriters(os.Stdout)
	}
	if runner.options.OutputFile != "" {
		outputFile, err := os.Create(runner.options.OutputFile)
		if err != nil {
			return nil, errorutil.New("could not create output file %s: %s", options.OutputFile, err)
		}
		runner.outputWriter.AddWriters(outputFile)
	}
	return runner, nil
}

// RunEnumeration runs the subdomain enumeration flow on the targets specified
func (r *Runner) Run(ctx context.Context) error {
	ipPortCount := make(map[string]int)
	skippedIPs := make(map[string]bool)
	maxPorts := r.options.MaxPortsPerIP

	resultCallback := func(result sources.Result) {
		// Skip IPs with too many open ports (likely honeypots)
		if maxPorts > 0 && result.IP != "" && result.Error == nil {
			if skippedIPs[result.IP] {
				return
			}
			ipPortCount[result.IP]++
			if ipPortCount[result.IP] > maxPorts {
				skippedIPs[result.IP] = true
				gologger.Warning().Msgf("Skipping IP %s: exceeded %d ports (likely honeypot)\n", result.IP, maxPorts)
				return
			}
		}

		optionFields := r.options.OutputFields
		switch {
		case result.Error != nil:
			gologger.Warning().Label(result.Source).Msgf("%s\n", result.Error.Error())
		case r.options.JSON:
			gologger.Verbose().Label(result.Source).Msgf("%s\n", result.JSON())
			r.outputWriter.WriteJsonData(result)
		case r.options.Raw:
			gologger.Verbose().Label(result.Source).Msgf("%s\n", result.RawData())
			r.outputWriter.WriteString(result.RawData())
		case r.options.CSV:
			gologger.Verbose().Label(result.Source).Msgf("host: %s\n", fmt.Sprint(result.IpPort()))
			r.outputWriter.WriteCSVData(result)
		default:
			port := fmt.Sprint(result.Port)
			replacer := strings.NewReplacer(
				"ip", result.IP,
				"host", result.Host,
				"port", port,
				"url", result.Url,
			)
			if (result.IP == "" || port == "0") && stringsutil.ContainsAny(r.options.OutputFields, "ip", "port") {
				optionFields = "host"
			}
			outData := replacer.Replace(optionFields)
			searchFor := []string{result.IP, port}
			if result.Host != "" || r.options.OutputFile != "" {
				searchFor = append(searchFor, result.Host)
			}
			if stringsutil.ContainsAny(outData, searchFor...) && !r.outputWriter.findDuplicate(outData, false) {
				if r.options.Verbose {
					// if output is verbose include source name
					gologger.Info().Label(result.Source).Msg(outData)
				} else {
					gologger.DefaultLogger.Print().Msg(outData)
				}
				r.outputWriter.WriteString(outData)
			}
		}
	}
	return r.service.ExecuteWithCallback(ctx, resultCallback)
}

// Close closes its resources
func (r *Runner) Close() {
	if r.outputWriter != nil {
		r.outputWriter.Close()
	}
}

const defaultIPBatchSize = 30

// ipQueryBuilder defines how each engine formats an IP query
type ipQueryBuilder struct {
	formatIP  func(ip string) string    // format a single IP condition
	joinOp    string                    // operator to join conditions
	wrapBatch func(query string) string // optional: wrap the final batch query
}

var engineIPBuilders = map[string]*ipQueryBuilder{
	"fofa": {
		formatIP:  func(ip string) string { return fmt.Sprintf(`ip="%s"`, ip) },
		joinOp:    " || ",
		wrapBatch: nil,
	},
	"quake": {
		formatIP:  func(ip string) string { return fmt.Sprintf(`ip:"%s"`, ip) },
		joinOp:    " || ",
		wrapBatch: func(q string) string { return fmt.Sprintf("(%s) AND status_code:200", q) },
	},
	"zoomeye": {
		formatIP:  func(ip string) string { return fmt.Sprintf(`ip="%s"`, ip) },
		joinOp:    " || ",
		wrapBatch: nil,
	},
	"hunter": {
		formatIP:  func(ip string) string { return fmt.Sprintf(`ip="%s"`, ip) },
		joinOp:    " || ",
		wrapBatch: nil,
	},
}

// getEngineSlice returns a pointer to the engine-specific query slice in Options
func getEngineSlice(options *Options, engine string) *goflags.StringSlice {
	switch engine {
	case "fofa":
		return &options.Fofa
	case "quake":
		return &options.Quake
	case "zoomeye":
		return &options.ZoomEye
	case "hunter":
		return &options.Hunter
	default:
		return nil
	}
}

func (r *Runner) ParseIPQuery() {
	ips := r.options.InputIP
	batchSize := defaultIPBatchSize
	batchCount := (len(ips) + batchSize - 1) / batchSize

	for i := 0; i < len(ips); i += batchSize {
		end := i + batchSize
		if end > len(ips) {
			end = len(ips)
		}
		batch := ips[i:end]

		for engine, builder := range engineIPBuilders {
			parts := make([]string, 0, len(batch))
			for _, ip := range batch {
				parts = append(parts, builder.formatIP(ip))
			}
			query := strings.Join(parts, builder.joinOp)
			if builder.wrapBatch != nil {
				query = builder.wrapBatch(query)
			}
			if slice := getEngineSlice(r.options, engine); slice != nil {
				*slice = append(*slice, query)
			}
		}
	}

	gologger.Info().Msgf("Split %d IPs into %d batches (batch size: %d)", len(ips), batchCount, batchSize)
	appendAllQueries(r.options)
}
