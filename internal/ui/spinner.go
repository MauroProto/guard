package ui

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Spinner frames for animated loading.
var frames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Spinner shows an animated spinner with a message.
type Spinner struct {
	msg    string
	done   chan struct{}
	wg     sync.WaitGroup
	result string
	noop   bool
}

// NewSpinner creates and starts a spinner with the given message.
func NewSpinner(msg string) *Spinner {
	s := &Spinner{
		msg:  msg,
		done: make(chan struct{}),
	}
	if !Interactive() {
		s.noop = true
		return s
	}
	s.wg.Add(1)
	go s.run()
	return s
}

func (s *Spinner) run() {
	defer s.wg.Done()
	i := 0
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			frame := frames[i%len(frames)]
			fmt.Fprintf(os.Stderr, "\r  %s%s%s %s%s", c(Magenta), frame, c(Reset), s.msg, clearLine())
			i++
		}
	}
}

// Stop stops the spinner and shows a success check.
func (s *Spinner) Stop() {
	if s.noop {
		Success(s.msg)
		return
	}
	close(s.done)
	s.wg.Wait()
	fmt.Fprintf(os.Stderr, "\r  %s%s%s %s%s\n", c(Green), IconCheck, c(Reset), s.msg, clearLine())
}

// StopFail stops the spinner and shows a failure cross.
func (s *Spinner) StopFail(msg string) {
	if s.noop {
		if msg == "" {
			msg = s.msg
		}
		Fail(msg)
		return
	}
	close(s.done)
	s.wg.Wait()
	if msg != "" {
		fmt.Fprintf(os.Stderr, "\r  %s%s%s %s%s\n", c(Red), IconCross, c(Reset), msg, clearLine())
	} else {
		fmt.Fprintf(os.Stderr, "\r  %s%s%s %s%s\n", c(Red), IconCross, c(Reset), s.msg, clearLine())
	}
}

// StopWarn stops the spinner and shows a warning.
func (s *Spinner) StopWarn(msg string) {
	if s.noop {
		if msg == "" {
			msg = s.msg
		}
		Warn(msg)
		return
	}
	close(s.done)
	s.wg.Wait()
	if msg != "" {
		fmt.Fprintf(os.Stderr, "\r  %s%s%s  %s%s\n", c(Yellow), IconWarn, c(Reset), msg, clearLine())
	} else {
		fmt.Fprintf(os.Stderr, "\r  %s%s%s  %s%s\n", c(Yellow), IconWarn, c(Reset), s.msg, clearLine())
	}
}

func clearLine() string {
	return "\033[K"
}

// Pause adds a small delay for visual pacing.
func Pause(d time.Duration) {
	if !Interactive() {
		return
	}
	time.Sleep(d)
}
