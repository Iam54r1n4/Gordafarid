package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

// Log levels
const (
	DEBUG = iota
	INFO
	WARN
	ERROR
	FATAL
)

// ANSI color codes
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
)

// Logger struct
type Logger struct {
	level    int
	log      *log.Logger
	logLevel map[int]string
	colors   map[int]string
}

var (
	instance *Logger
	once     = &sync.Once{}
)

// Initialize logger once (singleton)
func init() {
	once.Do(func() {
		instance = NewLogger(DEBUG, os.Stdout)
	})
}

// NewLogger initializes a new logger with the specified minimum level
func NewLogger(level int, output io.Writer) *Logger {
	return &Logger{
		level: level,
		log:   log.New(output, "", 0),
		logLevel: map[int]string{
			DEBUG: "DEBUG",
			INFO:  "INFO",
			WARN:  "WARN",
			ERROR: "ERROR",
			FATAL: "FATAL",
		},
		colors: map[int]string{
			DEBUG: ColorBlue,   // Blue for DEBUG
			INFO:  ColorGreen,  // Green for INFO
			WARN:  ColorYellow, // Yellow for WARN
			ERROR: ColorRed,    // Red for ERROR
			FATAL: ColorPurple, // Purple for FATAL
		},
	}
}

// SetLevel allows changing the log level dynamically
func SetLevel(level int) {
	instance.level = level
}

// logMessage is the internal logging method that checks the level and logs the message
func (l *Logger) logMessage(level int, args ...any) {
	if level >= l.level {
		timestamp := time.Now().Format(time.RFC3339)
		message := fmt.Sprint(args...)
		logOutput := fmt.Sprintf("[%s%s%s] [%s%s%s] - %s", ColorCyan, timestamp, ColorReset, l.colors[level], l.logLevel[level], ColorReset, message)
		l.log.Println(logOutput)
	}
}

// Global log methods

// Debug logs a message with DEBUG level
func Debug(args ...any) {
	instance.logMessage(DEBUG, args...)
}

// Info logs a message with INFO level
func Info(args ...any) {
	instance.logMessage(INFO, args...)
}

// Warn logs a message with WARN level
func Warn(args ...any) {
	instance.logMessage(WARN, args...)
}

// Error logs a message with ERROR level
func Error(args ...any) {
	instance.logMessage(ERROR, args...)
}

// Fatal logs a message with FATAL level and exits the program
func Fatal(args ...any) {
	instance.logMessage(FATAL, args...)
	os.Exit(1)
}
