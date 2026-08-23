package events

import "testing"

func TestQueueDepthTracksConsumerReads(t *testing.T) {
	b := New()
	_, ch, cancel := b.Subscribe()
	defer cancel()
	b.Publish(Event{ID: "1", Type: "test"})
	if depth, subscribers := b.Stats(); depth != 1 || subscribers != 1 {
		t.Fatalf("depth=%d subscribers=%d", depth, subscribers)
	}
	<-ch
	if depth, subscribers := b.Stats(); depth != 0 || subscribers != 1 {
		t.Fatalf("stale depth=%d subscribers=%d", depth, subscribers)
	}
}
