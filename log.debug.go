// +build !product

package instun

import (
	"log"
)

func debug(v... interface{}) {
	log.Println(v)
}

func debugf(f string, v... interface{}) {
	log.Printf(f, v)
}