package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
)

type Middleware func(http.Handler) http.Handler

func ChainMiddleware(middlewares ...Middleware) Middleware {
	return func(final http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}

func LoggingMiddleware(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ip, _, _ := net.SplitHostPort(r.RemoteAddr)

		fmt.Println("------ Incoming Request ------")
		fmt.Println("Method:", r.Method)
		fmt.Println("Path:", r.URL.Path)
		fmt.Println("IP:", ip)
		fmt.Println("User-Agent:", r.UserAgent())

		next.ServeHTTP(w, r)
	})
}

func RequestInspectionMiddleware(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		fmt.Println("Headers:")

		for k, v := range r.Header {
			fmt.Printf("%s: %v\n", k, v)
		}

		if r.Body != nil {

			bodyBytes, err := io.ReadAll(r.Body)
			if err == nil {

				fmt.Println("Body:", string(bodyBytes))

				r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
		}

		next.ServeHTTP(w, r)
	})
}
