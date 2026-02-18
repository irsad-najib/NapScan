package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var (
	instance *Logger
	once     sync.Once
)

type Logger struct {
	level  Level
	out    io.Writer
	logger *log.Logger
}

func Get() *Logger {
	once.Do(func() {
		lvl := LevelInfo
		envLevel := strings.ToLower(os.Getenv("LOG_LEVEL"))
		appEnv := strings.ToLower(os.Getenv("APP_ENV"))

		if envLevel == "debug" || appEnv == "development" {
			lvl = LevelDebug
		} else if envLevel == "warn" {
			lvl = LevelWarn
		} else if envLevel == "error" {
			lvl = LevelError
		}

		instance = &Logger{
			level:  lvl,
			out:    os.Stdout,
			logger: log.New(os.Stdout, "", 0),
		}
	})
	return instance
}

func (l *Logger) log(level Level, msg string) {
	if level < l.level {
		return
	}

	timestamp := time.Now().Format("2006/01/02 15:04:05")
	var levelStr string
	var colorCode string
	resetColor := "\033[0m"

	switch level {
	case LevelDebug:
		levelStr = "DEBUG"
		colorCode = "\033[36m" // Cyan
	case LevelInfo:
		levelStr = "INFO"
		colorCode = "\033[32m" // Green
	case LevelWarn:
		levelStr = "WARN"
		colorCode = "\033[33m" // Yellow
	case LevelError:
		levelStr = "ERROR"
		colorCode = "\033[31m" // Red
	}

	// Format: 2006/01/02 15:04:05 [INFO] Message
	// Colored output for terminal readability
	logMsg := fmt.Sprintf("%s %s[%s]%s %s", timestamp, colorCode, levelStr, resetColor, msg)
	l.logger.Println(logMsg)
}

func Debug(format string, v ...interface{}) {
	Get().log(LevelDebug, fmt.Sprintf(format, v...))
}

func Info(format string, v ...interface{}) {
	Get().log(LevelInfo, fmt.Sprintf(format, v...))
}

func Warn(format string, v ...interface{}) {
	Get().log(LevelWarn, fmt.Sprintf(format, v...))
}

func Error(format string, v ...interface{}) {
	Get().log(LevelError, fmt.Sprintf(format, v...))
}

func Fatal(format string, v ...interface{}) {
	Get().log(LevelError, fmt.Sprintf(format, v...))
	os.Exit(1)
}
