package app

import (
	"strings"

	"github.com/saba-futai/sudoku/internal/config"
	"github.com/saba-futai/sudoku/pkg/obfs/sudoku"
)

func BuildTables(cfg *config.Config) ([]*sudoku.Table, error) {
	patterns := cfg.CustomTables
	if len(patterns) == 0 && strings.TrimSpace(cfg.CustomTable) != "" {
		patterns = []string{cfg.CustomTable}
	}
	if len(patterns) == 0 {
		patterns = []string{""}
	}
	// Server-side convenience: when custom tables rotation is enabled, also accept the default table.
	// This avoids forcing clients to configure a custom layout in lockstep while keeping rotation available.
	if cfg != nil && cfg.Mode == "server" && len(patterns) > 0 && strings.TrimSpace(patterns[0]) != "" {
		patterns = append([]string{""}, patterns...)
	}

	tableSet, err := sudoku.NewTableSet(cfg.Key, cfg.ASCII, patterns)
	if err != nil {
		return nil, err
	}
	return tableSet.Candidates(), nil
}
