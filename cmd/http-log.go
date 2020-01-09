package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	. "github.com/logrusorgru/aurora"
)

func getHeader(r *http.Request, h string) (ret string) {
	hs := r.Header[h]
	if len(hs) >= 1 {
		ret = hs[0]
	} else {
		ret = fmt.Sprintf("<no %s>", h)
	}

	return
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// TODO: use r.Read() and StringBuilder?
		// FIXME: close body reader
		bs, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Fatalf("failed to get body: %v", err)
		}
		fmt.Printf("%s %s%s %s by %s\n", Green(r.Method), Cyan(r.Host), Cyan(r.RequestURI), Blue(r.Proto), Cyan(getHeader(r, "User-Agent")))
		fmt.Printf("%d bytes of %s \n", Cyan(r.ContentLength), Cyan(getHeader(r, "Content-Type")))
		fmt.Printf("%v\n", string(bs)) // assumes utf8
		fmt.Println()
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
