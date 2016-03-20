package recoverer

import (
	"fmt"
	"log"
	"net/http"
)

func RecoverHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic: %+v", err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "{\"code\":\"500\",\"title\":\"Internal Server Error\",\"detail\":\"Something went wrong.\"}]}")
			}
		}()
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}
