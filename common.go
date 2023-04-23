package ctidh

/*
#include <stdint.h>
__attribute__((weak))
void fillrandom_custom(
  void *const outptr,
  const size_t outsz,
  const uintptr_t context)
{
  go_fillrandom(context, outptr, outsz);
}
*/
import "C"
import (
	"fmt"
	"io"
	"unsafe"

	gopointer "github.com/mattn/go-pointer"
)

//export go_fillrandom
func go_fillrandom(context unsafe.Pointer, outptr unsafe.Pointer, outsz C.size_t) {
	rng := gopointer.Restore(context).(io.Reader)
	buf := make([]byte, outsz)
	count, err := rng.Read(buf)
	if err != nil {
		panic(err)
	}
	if count != int(outsz) {
		panic("rng fail")
	}
	p := uintptr(outptr)
	for i := 0; i < int(outsz); {
		(*(*uint32)(unsafe.Pointer(p))) = uint32(buf[i])
		p += 4
		i += 4
	}
}

// Name returns the string naming of the current
// CTIDH that this binding is being used with;
// Valid values are:
//
// CTIDH-511, CTIDH-512, CTIDH-1024 and, CTIDH-2048.
func Name() string {
	return fmt.Sprintf("CTIDH-%d", C.BITS)
}

func validateBitSize(bits int) {
	switch bits {
	case 511:
	case 512:
	case 1024:
	case 2048:
	default:
		panic("CTIDH/cgo: BITS must be 511 or 512 or 1024 or 2048")
	}
}
