package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// TODO: use r.Read() and StringBuilder?
		// FIXME: close body reader
		bs, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Fatalf("failed to get body: %v", err)
		}
		fmt.Printf("%s %s %s%s\n", r.Proto, r.Method, r.Host, r.RequestURI)
		fmt.Printf("%s: %d bytes / %s \n", r.Header["User-Agent"][0], r.ContentLength, r.Header["Content-Type"][0])
		fmt.Printf("%v\n", string(bs)) // assumes utf8
		fmt.Println()
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
