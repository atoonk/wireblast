package app

import (
	"errors"
	"fmt"
	"os"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/stats"
	"github.com/atoonk/wireblast/internal/statsexport"
)

type statsOutput struct {
	file   *os.File
	stream *statsexport.Writer
}

func openStatsOutput(cfg *config.Config) (*statsOutput, error) {
	if cfg.StatsFile == "" {
		return nil, nil
	}
	file, err := os.OpenFile(cfg.StatsFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return nil, fmt.Errorf("create statistics file %s: %w", cfg.StatsFile, err)
	}
	stream, err := statsexport.New(statsexport.Format(cfg.StatsFormat), file)
	if err != nil {
		closeErr := file.Close()
		removeErr := os.Remove(cfg.StatsFile)
		return nil, errors.Join(err, closeErr, removeErr)
	}
	return &statsOutput{file: file, stream: stream}, nil
}

func (o *statsOutput) Sample(s *stats.Snapshot) error { return o.stream.Sample(s) }
func (o *statsOutput) Final(s *stats.Snapshot) error  { return o.stream.Final(s) }

func (o *statsOutput) Close() error {
	return errors.Join(o.stream.Close(), o.file.Close())
}
