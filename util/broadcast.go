package util

const listenerBufferSize = 64

type Broadcast struct {
	listeners []chan interface{}
	reg       chan (chan interface{})
	unreg     chan (chan interface{})
	in        chan interface{}
}

func NewBroadcast() *Broadcast {
	b := &Broadcast{
		listeners: make([]chan interface{}, 0),
		reg:       make(chan (chan interface{})),
		unreg:     make(chan (chan interface{})),
		in:        make(chan interface{}),
	}

	go func() {
		for {
			select {
			case l := <-b.unreg:
				// remove L from b.listeners
				// this operation is slow: O(n) but not used frequently
				// unlike iterating over listeners
				oldListeners := b.listeners
				b.listeners = make([]chan interface{}, 0, len(oldListeners))
				removed := false
				for _, oldL := range oldListeners {
					if l != oldL {
						b.listeners = append(b.listeners, oldL)
					} else {
						removed = true
					}
				}
				if removed {
					close(l)
				}

			case l := <-b.reg:
				b.listeners = append(b.listeners, l)

			case item := <-b.in:
				for _, l := range b.listeners {
					select {
					case l <- item:
					default:
						// Drop update for slow listeners to avoid global backpressure.
					}
				}
			}
		}
	}()

	return b
}

func (b *Broadcast) In() chan interface{} {
	return b.in
}

func (b *Broadcast) Reg() chan interface{} {
	listener := make(chan interface{}, listenerBufferSize)
	b.reg <- listener
	return listener
}

func (b *Broadcast) UnReg(listener chan interface{}) {
	b.unreg <- listener
}
