package store

import "context"

// Store is the gateway's view of Redis: a place to append events
// and read back single keys. Kept deliberately small.
type Store interface {
	Append(ctx context.Context, stream string, fields map[string]any) error
	Get(ctx context.Context, key string) (value string, found bool, err error)
	Close() error
}
