package cli

import "fmt"

// StartupErr signals exit code 2 (config/cert/startup failure).
type StartupErr struct {
	Msg string
	Err error
}

func (e *StartupErr) Error() string { return fmt.Sprintf("%s: %v", e.Msg, e.Err) }
func (e *StartupErr) Unwrap() error { return e.Err }

func StartupError(msg string, err error) error { return &StartupErr{Msg: msg, Err: err} }

// RuntimeErr signals exit code 1 (required destination failed).
type RuntimeErr struct {
	Code int
}

func (e *RuntimeErr) Error() string { return fmt.Sprintf("runtime failure (exit %d)", e.Code) }

func RuntimeError(code int) error { return &RuntimeErr{Code: code} }
