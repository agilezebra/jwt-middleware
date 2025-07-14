// Simple logger to mimic the traefik logger in the absence of actual access to it.
// For DEBUG we output to stdout add this will be handled per https://github.com/traefik/traefik/issues/8204#issuecomment-1012952477
// For ERROR we just use the log package and traefik will handled.
// For INFO and WARN we output to stderr in a matching format.
package logger

import (
	"fmt"
	"log"
	"os"
	"time"
)

const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorGrey   = "\033[90m"
)

func Log(level string, format string, fields ...any) {
	// Log DEBUG and ERROR using the traefik . Log INFO and WARN directly to stderr in a matching format.
	var color string
	switch level {
	case "DEBUG":
		fmt.Printf(format, fields...)
		return
	case "INFO":
		color = colorGreen
		level = "INF"
	case "WARN":
		color = colorYellow
		level = "WRN"
	case "ERROR":
		log.Printf(format, fields...)
		return
	default:
		log.Printf("Unknown logging level: %s, when logging %s with fields %v", level, format, fields)
		return
	}

	fmt.Fprintf(os.Stderr, "%s%s %s%s%s %s%s%s\n",
		colorGrey, time.Now().UTC().Format(time.RFC3339), // Timestamp in grey
		color, level, colorReset, // Level in color
		colorBold, fmt.Sprintf(format, fields...), colorReset, // Content in bold
	)
}
