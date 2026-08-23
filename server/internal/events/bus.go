package events

import (
	"sync"

	"github.com/frp-admin/frp-admin/server/internal/metrics"
)

type Event struct {
	ID, Type string
	Data     []byte
}
type Bus struct {
	mu   sync.RWMutex
	next int
	subs map[int]chan Event
}

func New() *Bus {
	b := &Bus{subs: map[int]chan Event{}}
	metrics.Default.SetEventStatsProvider(b.Stats)
	return b
}
func (b *Bus) Subscribe() (int, <-chan Event, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.next
	b.next++
	ch := make(chan Event, 16)
	b.subs[id] = ch
	b.observe()
	return id, ch, func() {
		b.mu.Lock()
		if c, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(c)
		}
		b.observe()
		b.mu.Unlock()
	}
}
func (b *Bus) Publish(e Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subs {
		select {
		case ch <- e:
		default:
			metrics.Default.EventDropped()
		}
	}
	b.observe()
}
func (b *Bus) observe() {
	depth := 0
	for _, ch := range b.subs {
		depth += len(ch)
	}
	metrics.Default.EventQueue(depth, len(b.subs))
}
func (b *Bus) Stats() (int, int) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	depth := 0
	for _, ch := range b.subs {
		depth += len(ch)
	}
	return depth, len(b.subs)
}
