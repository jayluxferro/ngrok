package util

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"sync"
)

var (
	globalRand *mrand.Rand
	randOnce   sync.Once
	randMutex  sync.Mutex
)

func initGlobalRand(seed int64) {
	globalRand = mrand.New(mrand.NewSource(seed))
}

func RandomSeed() (seed int64, err error) {
	err = binary.Read(rand.Reader, binary.LittleEndian, &seed)
	return
}

// InitGlobalRand initializes the global random number generator with a secure seed
func InitGlobalRand(seed int64) {
	randOnce.Do(func() {
		initGlobalRand(seed)
	})
}

// GetGlobalRand returns the global random number generator. Callers that need
// a random value should use GlobalInt31/GlobalUint32 instead: the generator is
// shared across connections, and math/rand.Rand is not safe for concurrent
// use, so reads must happen under the lock.
func GetGlobalRand() *mrand.Rand {
	randMutex.Lock()
	defer randMutex.Unlock()
	if globalRand == nil {
		// Fallback: use default source if not initialized
		// This shouldn't happen in normal operation
		seed, _ := RandomSeed()
		initGlobalRand(seed)
	}
	return globalRand
}

// GlobalInt31 returns a random int31 from the shared generator, locked.
func GlobalInt31() int32 {
	randMutex.Lock()
	defer randMutex.Unlock()
	if globalRand == nil {
		seed, _ := RandomSeed()
		initGlobalRand(seed)
	}
	return globalRand.Int31()
}

// GlobalUint32 returns a random uint32 from the shared generator, locked.
func GlobalUint32() uint32 {
	randMutex.Lock()
	defer randMutex.Unlock()
	if globalRand == nil {
		seed, _ := RandomSeed()
		initGlobalRand(seed)
	}
	return globalRand.Uint32()
}

// creates a random identifier of the specified length
func RandId(idlen int) string {
	b := make([]byte, idlen)
	var randVal uint32
	for i := 0; i < idlen; i++ {
		byteIdx := i % 4
		if byteIdx == 0 {
			randVal = GlobalUint32()
		}
		b[i] = byte((randVal >> (8 * uint(byteIdx))) & 0xFF)
	}
	return fmt.Sprintf("%x", b)
}

// like RandId, but uses a crypto/rand for secure random identifiers
func SecureRandId(idlen int) (id string, err error) {
	b := make([]byte, idlen)
	n, err := rand.Read(b)

	if n != idlen {
		err = fmt.Errorf("Only generated %d random bytes, %d requested", n, idlen)
		return
	}

	if err != nil {
		return
	}

	id = fmt.Sprintf("%x", b)
	return
}

func SecureRandIdOrPanic(idlen int) string {
	id, err := SecureRandId(idlen)
	if err != nil {
		panic(err)
	}
	return id
}
