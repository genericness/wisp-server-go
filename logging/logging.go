package logging

import (
	"log"
)

func Info(message string) {
	log.Printf("[INFO] %s", message)
}

func Debug(message string) {
	log.Printf("[DEBUG] %s", message)
}

func Warn(message string) {
	log.Printf("[WARN] %s", message)
}

func Error(message string) {
	log.Printf("[ERROR] %s", message)
}

func Fatal(message string) {
	log.Fatalf("[FATAL] %s", message)
}

func Printf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

func Println(v ...interface{}) {
	log.Println(v...)
}

func Fatalf(format string, v ...interface{}) {
	log.Fatalf(format, v...)
}

func Fatalln(v ...interface{}) {
	log.Fatalln(v...)
}