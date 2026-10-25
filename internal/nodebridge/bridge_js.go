//go:build js && wasm

package nodebridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall/js"
)

func Host() js.Value { return js.Global().Get("mcpsenseHost") }

type result struct {
	value js.Value
	err   error
}

// Every host call settles once, including cancellation. Release the Go callback
// only after host settlement so late Node events cannot call a released func.
func call(ctx context.Context, method string, args ...interface{}) (value js.Value, err error) {
	if ctx.Err() != nil {
		return js.Undefined(), ctx.Err()
	}
	if Host().Type() != js.TypeObject {
		return js.Undefined(), errors.New("Node runtime bridge unavailable")
	}
	done := make(chan result, 1)
	cb := js.FuncOf(func(_ js.Value, values []js.Value) interface{} {
		r := result{value: js.Undefined()}
		if len(values) < 2 {
			r.err = errors.New("invalid runtime response")
		} else if !values[0].IsNull() && !values[0].IsUndefined() {
			r.err = errors.New("Node runtime operation failed")
		} else {
			r.value = values[1]
		}
		done <- r
		return nil
	})
	defer cb.Release()
	defer func() {
		if recover() != nil {
			value = js.Undefined()
			err = errors.New("Node runtime operation unavailable")
		}
	}()
	args = append(args, cb)
	abort := Host().Call(method, args...)
	select {
	case r := <-done:
		return r.value, r.err
	case <-ctx.Done():
		if abort.Type() == js.TypeFunction {
			abort.Invoke()
		}
		<-done
		return js.Undefined(), ctx.Err()
	}
}

func Abs(p string) (string, error) {
	if Host().Type() != js.TypeObject {
		return "", errors.New("Node runtime unavailable")
	}
	return Host().Call("absolute", p).String(), nil
}
func Dir(p string) string  { return Host().Call("dirname", p).String() }
func Base(p string) string { return Host().Call("basename", p).String() }
func MkdirAll(p string, mode os.FileMode) error {
	_, err := call(context.Background(), "mkdir", p, int(mode.Perm()))
	return err
}
func RuntimeID() string {
	if Host().Type() != js.TypeObject {
		return "js/wasm:unknown"
	}
	return "js/wasm:" + Host().Get("platform").String()
}

type Reader struct {
	ctx    context.Context
	id     int
	closed bool
}

func (r *Reader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	n := len(p)
	if n > 64<<10 {
		n = 64 << 10
	}
	v, err := call(r.ctx, "read", r.id, n)
	if err != nil {
		return 0, err
	}
	if v.Get("length").Int() == 0 {
		return 0, io.EOF
	}
	if v.Get("length").Int() > n {
		return 0, fmt.Errorf("runtime stream exceeded chunk limit")
	}
	return js.CopyBytesToGo(p, v), nil
}
func (r *Reader) Close() error {
	if !r.closed {
		r.closed = true
		Host().Call("closeStream", r.id)
	}
	return nil
}

type Writer struct {
	ctx    context.Context
	id     int
	closed bool
}

func (w *Writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	if len(p) > 4<<20 {
		return 0, fmt.Errorf("runtime write exceeds limit")
	}
	b := js.Global().Get("Uint8Array").New(len(p))
	js.CopyBytesToJS(b, p)
	_, err := call(w.ctx, "write", w.id, b)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
func (w *Writer) Close() error {
	if !w.closed {
		w.closed = true
		Host().Call("closeInput", w.id)
	}
	return nil
}

func StartProcess(ctx context.Context, parts []string) (io.WriteCloser, io.ReadCloser, func(), error) {
	args := js.Global().Get("Array").New(len(parts))
	for i, p := range parts {
		args.SetIndex(i, p)
	}
	v, err := call(ctx, "startProcess", args)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not start authorized MCP server")
	}
	id := v.Get("id").Int()
	r := &Reader{ctx: ctx, id: v.Get("stream").Int()}
	w := &Writer{ctx: ctx, id: id}
	stop := func() { _ = w.Close(); _ = r.Close(); Host().Call("closeProcess", id) }
	return w, r, stop, nil
}
