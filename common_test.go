package ctidh

import (
	"bytes"
	"testing"

	gopointer "github.com/mattn/go-pointer"
)

func TestFillRandom(t *testing.T) {
	message := []byte("AAAA")
	rng := bytes.NewReader(message)
	p := gopointer.Save(rng)
	outsz := 4
	out := test_c_buf(outsz)
	test_go_fillrandom(p, out, outsz)
	t.Logf("out: `%s`", test_GoString(out, outsz))
}
