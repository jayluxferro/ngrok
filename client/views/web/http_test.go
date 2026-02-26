package web

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestFilterTxnsConcurrentAccess(t *testing.T) {
	whv := &WebHttpView{
		idToTxn: make(map[string]*SerializedTxn),
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			whv.idToTxnMu.Lock()
			whv.idToTxn[string(rune(i))] = &SerializedTxn{}
			whv.idToTxnMu.Unlock()
		}(i)
		go func(i int) {
			defer wg.Done()
			whv.idToTxnMu.RLock()
			_ = whv.idToTxn[string(rune(i))]
			whv.idToTxnMu.RUnlock()
		}(i)
	}
	wg.Wait()

	req := httptest.NewRequest(http.MethodGet, "/http/in", nil)
	_ = req
}

