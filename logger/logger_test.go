package logger

import (
	"bytes"
	"io"
	"log"
	"os"
	"regexp"
	"testing"
)

// captureOutput captures and returns the output of the function based on the capture type.
func captureOutput(tester *testing.T, function func(), capture string) string {
	read, write, err := os.Pipe()
	if err != nil {
		tester.Fatalf("Failed to create stdout pipe: %v", err)
	}
	defer read.Close() //nolint:errcheck

	var old *os.File
	var oldLog io.Writer
	var logBuffer bytes.Buffer

	switch capture {
	case "stdout":
		old = os.Stdout
		os.Stdout = write
	case "stderr":
		old = os.Stderr
		os.Stderr = write
	case "log":
		oldLog = log.Writer()
		log.SetOutput(&logBuffer)
	}

	function()
	write.Close() //nolint:errcheck

	switch capture {
	case "stdout":
		os.Stdout = old
	case "stderr":
		os.Stderr = old
	case "log":
		log.SetOutput(oldLog)
		return logBuffer.String()
	}

	buffer, err := io.ReadAll(read)
	if err != nil {
		tester.Fatalf("Failed to read buffer: %v", err)
	}

	return string(buffer)
}

func TestLog(tester *testing.T) {
	tests := []struct {
		level           string
		message         string
		fields          []any
		capture         string
		expectedPattern string
	}{
		{"DEBUG", "Debug message with %s and %s", []any{"parameter", "other"}, "stdout", `^Debug message with parameter and other$`},
		{"INFO", "Info message with %s", []any{"parameter"}, "stderr", `^\x1b\[90m\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z \x1b\[32mINF\x1b\[0m \x1b\[1mInfo message with parameter\x1b\[0m\n$`},
		{"WARN", "Warning message", []any{}, "stderr", `^\x1b\[90m\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z \x1b\[33mWRN\x1b\[0m \x1b\[1mWarning message\x1b\[0m\n$`},
		{"ERROR", "Error message with %s", []any{"parameter"}, "log", `^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} Error message with parameter\n$`},
		{"OTHER", "Unknown level %s", []any{"parameter"}, "log", `^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} Unknown logging level: OTHER, when logging Unknown level %s with fields \[parameter\]\n$`},
	}

	for _, test := range tests {
		tester.Run(test.level, func(tester *testing.T) {
			stderr := captureOutput(tester, func() { Log(test.level, test.message, test.fields...) }, test.capture)

			matched, err := regexp.MatchString(test.expectedPattern, stderr)
			if err != nil {
				tester.Fatalf("Failed to compile regex: %v", err)
			}
			if !matched {
				tester.Errorf("Stderr output doesn't match expected pattern. Got: %q", stderr)
			}
		})
	}
}
