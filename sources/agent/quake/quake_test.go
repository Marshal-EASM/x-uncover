package quake

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestResponseUnmarshalStringRateLimitCode(t *testing.T) {
	var response Response
	err := json.Unmarshal([]byte(`{"code":"q3005","message":"调用API过于频繁","data":{},"meta":{}}`), &response)
	require.NoError(t, err)
	require.Equal(t, "q3005", response.Code)
	require.True(t, response.IsRateLimited())
	require.False(t, response.IsSuccess())
	require.Empty(t, response.Data)
	require.JSONEq(t, `{}`, string(response.RawData))
}

func TestResponseUnmarshalNumericCodeAndData(t *testing.T) {
	var response Response
	err := json.Unmarshal([]byte(`{"code":0,"message":"ok","data":[{"ip":"1.1.1.1","port":443,"service":{"http":{"status_code":200},"dns":{}},"location":{},"asn":13335}],"meta":{}}`), &response)
	require.NoError(t, err)
	require.Equal(t, "0", response.Code)
	require.True(t, response.IsSuccess())
	require.Len(t, response.Data, 1)
	require.Equal(t, "1.1.1.1", response.Data[0].Ip)
	require.Equal(t, 443, response.Data[0].Port)
}

func TestHandleQuakeRateLimitSleepsBeforeRetry(t *testing.T) {
	originalSleep := quakeSleep
	originalBackoff := quakeBackoffDuration
	t.Cleanup(func() {
		quakeSleep = originalSleep
		quakeBackoffDuration = originalBackoff
	})

	var slept time.Duration
	quakeBackoffDuration = func() time.Duration { return 2 * time.Second }
	quakeSleep = func(delay time.Duration) { slept = delay }

	retried := handleQuakeRateLimit(&Response{Code: "q3005", Message: "调用API过于频繁"})
	require.True(t, retried)
	require.Equal(t, 2*time.Second, slept)

	retried = handleQuakeRateLimit(&Response{Code: "0", Message: "ok"})
	require.False(t, retried)
	require.Equal(t, 2*time.Second, slept)
}
