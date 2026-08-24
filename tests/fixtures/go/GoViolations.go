package main

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type MyError struct{ msg string }

func (e *MyError) Error() string { return e.msg }

type Config struct {
	Settings map[string]string
}

//go:noescape
func riskyOp(p *byte) {}

func buildWire() [5]byte {
	b := [...]byte{100, 3: 200, 0}
	return b
}

func mayFail() error {
	var err *MyError = nil
	return err
}

func processFile() {
	start := time.Now()
	defer fmt.Println(time.Since(start))
}

func spawnLoopBug() {
	for i := 0; i < 10; i++ {
		go func() {
			fmt.Println(i)
		}()
	}
}

func (s Config) SetKey(k, v string) {
	s.Settings[k] = v
}

func runForever(messages <-chan string) {
	for {
		select {
		case msg := <-messages:
			fmt.Println(msg)
		}
	}
}

func verify(a, b, expected []byte) bool {
	return len(a) == len(expected)
}

func useConfig() {
	cfg := Config{}
	cfg.Settings["key"] = "value"
}

func sliceAlias() {
	original := []int{1, 2, 3, 4, 5}
	slice := original[1:3]
	slice[0] = 99
	_ = append(slice, 4)
}

func shadowErr() error {
	err := errors.New("validate")
	if err != nil {
		return err
	}
	if true {
		_, err := fmt.Errorf("auth")
		if err != nil {
			return err
		}
	}
	return nil
}

func _unused(ctx context.Context) {
	_ = ctx
}
