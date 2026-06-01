package tunnel

import "context"

type NoopTunneler struct{}

func NewNoop() *NoopTunneler {
	return &NoopTunneler{}
}

func (t *NoopTunneler) Start(_ context.Context, _ Settings) error {
	return nil
}
