package main

import (
	"errors"
	"fmt"
	"os"

	"ssl-update/internal/cli"
	_ "ssl-update/internal/destination/aliyun_esa"
	_ "ssl-update/internal/destination/safeline"
)

func main() {
	err := cli.NewRootCmd().Execute()
	if err == nil {
		return
	}
	var startErr *cli.StartupErr
	if errors.As(err, &startErr) {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	var runErr *cli.RuntimeErr
	if errors.As(err, &runErr) {
		os.Exit(runErr.Code)
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
