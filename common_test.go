package ctidh

import (
	"bytes"
	"testing"
	"unsafe"

	gopointer "github.com/mattn/go-pointer"
)

func TestFillRandom(t *testing.T) {
	rng := bytes.NewReader([]byte("hello"))
	p := gopointer.Save(rng)
	outsz := 5
	out := test_c_buf(outsz)
	outptr := unsafe.Pointer(&out)
	test_go_fillrandom(p, outptr, outsz)
	t.Logf("out: %s", test_GoString(out))
}
