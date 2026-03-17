package runner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseIPQueryUsesExplicitEnginesOnly(t *testing.T) {
	r := &Runner{options: &Options{
		InputIP:        []string{"1.1.1.1", "2.2.2.2"},
		Engine:         []string{"quake"},
		EngineExplicit: true,
	}}

	r.ParseIPQuery()

	require.Equal(t, []string{"quake"}, []string(r.options.Engine))
	require.Equal(t, []string{"(ip:\"1.1.1.1\" || ip:\"2.2.2.2\") AND status_code:200"}, []string(r.options.Quake))
	require.Equal(t, []string{"(ip:\"1.1.1.1\" || ip:\"2.2.2.2\") AND status_code:200"}, []string(r.options.Query))
	require.Equal(t, map[string][]string{
		"quake": {"(ip:\"1.1.1.1\" || ip:\"2.2.2.2\") AND status_code:200"},
	}, r.options.NewQuery)
	require.Empty(t, r.options.Fofa)
	require.Empty(t, r.options.ZoomEye)
	require.Empty(t, r.options.Hunter)
}

func TestParseIPQueryUsesAllSupportedEnginesByDefault(t *testing.T) {
	r := &Runner{options: &Options{
		InputIP: []string{"1.1.1.1"},
		Engine:  []string{"shodan"},
	}}

	r.ParseIPQuery()

	require.Len(t, r.options.Fofa, 1)
	require.Len(t, r.options.Quake, 1)
	require.Len(t, r.options.ZoomEye, 1)
	require.Len(t, r.options.Hunter, 1)
	require.Contains(t, []string(r.options.Engine), "shodan")
	require.Contains(t, []string(r.options.Engine), "fofa")
	require.Contains(t, []string(r.options.Engine), "quake")
	require.Contains(t, []string(r.options.Engine), "zoomeye")
	require.Contains(t, []string(r.options.Engine), "hunter")
	require.Len(t, r.options.NewQuery, 4)
}
