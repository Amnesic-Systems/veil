package tunnel

import (
	"context"
	"sync"
)

type NoopTunneler struct{}

func NewNoop() *NoopTunneler {
	return &NoopTunneler{}
}

func (t *NoopTunneler) Start(_ context.Context, wg *sync.WaitGroup, _ uint32) {
	wg.Done()
}
