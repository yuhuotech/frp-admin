package operation

import "sync/atomic"

type Lock struct{ held atomic.Bool }

func (l *Lock) TryAcquire() bool { return l.held.CompareAndSwap(false, true) }
func (l *Lock) Release()         { l.held.Store(false) }
func (l *Lock) Held() bool       { return l.held.Load() }
