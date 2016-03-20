package logger

import (
	"log"
	"net/http"
	"time"
)

type Logger struct {
	next http.Handler
}

func NewLogger(handler http.Handler) http.Handler {
	return &Logger{handler}
}

func (l *Logger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t1 := time.Now()
	l.next.ServeHTTP(w, r)
	t2 := time.Now()
	log.Printf("- %s - %s %q - %s - %v\n", r.RemoteAddr, r.Method, r.URL.Path, r.Header.Get("User-Agent"), t2.Sub(t1))
}
