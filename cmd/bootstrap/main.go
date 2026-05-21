// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/twelho/talos-bootstrap/cmd/bootstrap/cli"
)

func main() {
	configureLogging()

	if err := cli.Root().Execute(); err != nil {
		log.Error().Err(err).Msg("command failed")
		os.Exit(1)
	}
}

func configureLogging() {
	zerolog.TimeFieldFormat = time.RFC3339
	zerolog.CallerMarshalFunc = func(_ uintptr, file string, line int) string {
		return filepath.ToSlash(file) + ":" + strconv.Itoa(line)
	}

	writer := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
		PartsOrder: []string{
			zerolog.TimestampFieldName,
			zerolog.LevelFieldName,
			zerolog.CallerFieldName,
			zerolog.MessageFieldName,
		},
	}
	log.Logger = zerolog.New(writer).With().Timestamp().Caller().Logger()
}
