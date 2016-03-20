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
				w.Header().Set("Content-Type", "application/vnd.api+json")
				fmt.Fprintf(w, "{\"errors\":[{\"id\":\"internal_server_error\",\"status\":500,\"title\":\"Internal Server Error\",\"detail\":\"Something went wrong.\"}]}")
			}
		}()
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}
