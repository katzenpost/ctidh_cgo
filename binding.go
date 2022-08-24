package ctidh

// #include "binding.h"
// #include <csidh.h>
import "C"
import (
	"errors"
	"unsafe"
)

var (
	// PublicKeySize is the size in bytes of the public key.
	PublicKeySize int

	// PrivateKeySize is the size in bytes of the private key.
	PrivateKeySize int

	// ErrBlindDataSizeInvalid indicates that the blinding data size was invalid.
	ErrBlindDataSizeInvalid error = errors.New("CTIDH/cgo: blinding data size invalid")

	// ErrPublicKeyValidation indicates a public key validation failure.
	ErrPublicKeyValidation error = errors.New("CTIDH/cgo: public key validation failure")

	// ErrPublicKeySize indicates the raw data is not the correct size for a public key.
	ErrPublicKeySize error = errors.New("CTIDH/cgo: raw public key data size is wrong")

	// ErrPrivateKeySize indicates the raw data is not the correct size for a private key.
	ErrPrivateKeySize error = errors.New("CTIDH/cgo: raw private key data size is wrong")

	// ErrCTIDH indicates a group action failure.
	ErrCTIDH error = errors.New("CTIDH/cgo: group action failure")
)

// PublicKey is a public CTIDH key.
type PublicKey struct {
	publicKey C.public_key
}

// Reset resets the PublicKey to all zeros.
func (p *PublicKey) Reset() {
	zeros := make([]byte, PublicKeySize)
	err := p.FromBytes(zeros)
	if err != nil {
		panic(err)
	}
}

// Bytes returns the PublicKey as a byte slice.
func (p *PublicKey) Bytes() []byte {
	return C.GoBytes(unsafe.Pointer(&p.publicKey.A.x.c), C.int(C.UINTBIG_LIMBS*8))
}

// FromBytes loads a PublicKey from the given byte slice.
func (p *PublicKey) FromBytes(data []byte) error {
	if len(data) != PublicKeySize {
		return ErrPublicKeySize
	}

	p.publicKey = *((*C.public_key)(unsafe.Pointer(&data[0])))
	if !C.validate(&p.publicKey) {
		return ErrPublicKeyValidation
	}

	return nil
}

// Blind performs a blinding operation
// and mutates the public key.
func (p *PublicKey) Blind(data []byte) error {
	if len(data) != PrivateKeySize {
		return ErrBlindDataSizeInvalid
	}

	privKey := new(PrivateKey)
	err := privKey.FromBytes(data)
	if err != nil {
		return err
	}

	pubKey := groupAction(privKey, p)
	p.publicKey = pubKey.publicKey

	return nil
}

// PrivateKey is a private CTIDH key.
type PrivateKey struct {
	privateKey C.private_key
}

// Reset resets the PrivateKey to all zeros.
func (p *PrivateKey) Reset() {
	zeros := make([]byte, PrivateKeySize)
	err := p.FromBytes(zeros)
	if err != nil {
		panic(err)
	}
}

// Bytes serializes PrivateKey into a byte slice.
func (p *PrivateKey) Bytes() []byte {
	return C.GoBytes(unsafe.Pointer(&p.privateKey), C.primes_num)
}

// FromBytes loads a PrivateKey from the given byte slice.
func (p *PrivateKey) FromBytes(data []byte) error {
	if len(data) != PrivateKeySize {
		return ErrPrivateKeySize
	}

	p.privateKey = *((*C.private_key)(unsafe.Pointer(&data[0])))
	return nil
}

// DerivePublicKey derives a public key given a private key.
func DerivePublicKey(privKey *PrivateKey) *PublicKey {
	var base C.public_key
	baseKey := new(PublicKey)
	baseKey.publicKey = base
	return groupAction(privKey, baseKey)
}

// GenerateKeyPair generates a new private and then
// attempts to compute the public key.
func GenerateKeyPair() (*PrivateKey, *PublicKey) {
	privKey := new(PrivateKey)
	C.csidh_private(&privKey.privateKey)
	return privKey, DerivePublicKey(privKey)
}

func groupAction(privateKey *PrivateKey, publicKey *PublicKey) *PublicKey {
	sharedKey := new(PublicKey)
	ok := C.csidh(&sharedKey.publicKey, &publicKey.publicKey, &privateKey.privateKey)
	if !ok {
		panic(ErrCTIDH)
	}
	return sharedKey
}

// DeriveSecret derives a shared secret.
func DeriveSecret(privateKey *PrivateKey, publicKey *PublicKey) []byte {
	sharedSecret := groupAction(privateKey, publicKey)
	return sharedSecret.Bytes()
}

// Blind performs the blinding operation against the
// two byte slices which must be the correct lengths:
//
// * publicKeyBytes must be the size of a public key.
//
// * blindingFactor must be the size of a private key.
//
// See also PublicKey's Blind method.
func Blind(publicKeyBytes, blindingFactor []byte) ([]byte, error) {
	if len(publicKeyBytes) != PublicKeySize {
		return nil, ErrBlindDataSizeInvalid
	}

	if len(blindingFactor) != PrivateKeySize {
		return nil, ErrBlindDataSizeInvalid
	}

	pubKey := new(PublicKey)
	err := pubKey.FromBytes(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	pubKey.Blind(blindingFactor)
	return pubKey.Bytes(), nil
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

func init() {
	validateBitSize(C.BITS)
	PrivateKeySize = C.primes_num
	switch C.BITS {
	case 511:
		PublicKeySize = 64
	case 512:
		PublicKeySize = 64
	case 1024:
		PublicKeySize = 128
	case 2048:
		PublicKeySize = 256
	}
}
