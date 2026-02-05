package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/saba-futai/sudoku/internal/app"
	"github.com/saba-futai/sudoku/internal/config"
	"github.com/saba-futai/sudoku/internal/reverse"
	"github.com/saba-futai/sudoku/pkg/crypto"
)

var (
	configPath  = flag.String("c", "config.json", "Path to configuration file")
	testConfig  = flag.Bool("test", false, "Test configuration file and exit")
	keygen      = flag.Bool("keygen", false, "Generate a new Ed25519 key pair")
	more        = flag.String("more", "", "Generate more Private key (hex) for split key generations")
	linkInput   = flag.String("link", "", "Start client directly from a sudoku:// short link")
	exportLink  = flag.Bool("export-link", false, "Print sudoku:// short link generated from the config")
	publicHost  = flag.String("public-host", "", "Advertised server host for short link generation (server mode); supports host or host:port")
	setupWizard = flag.Bool("tui", false, "Launch interactive TUI to create config before starting")

	revDial     = flag.String("rev-dial", "", "Dial a reverse TCP-over-WebSocket endpoint (ws:// or wss://) and forward from rev-listen")
	revListen   = flag.String("rev-listen", "", "Local TCP listen address for reverse forwarder (e.g., 127.0.0.1:2222)")
	revInsecure = flag.Bool("rev-insecure", false, "Skip TLS verification for wss reverse dial (testing only)")
)

func main() {
	flag.Parse()

	if *revDial != "" || *revListen != "" {
		if *revDial == "" || *revListen == "" {
			log.Fatalf("reverse forwarder requires both -rev-dial and -rev-listen")
		}
		if err := reverse.ServeLocalWSForward(*revListen, *revDial, *revInsecure); err != nil {
			log.Fatal(err)
		}
		return
	}

	if *keygen {
		if *more != "" {
			x, err := crypto.ParsePrivateScalar(*more)
			if err != nil {
				log.Fatalf("Invalid private key: %v", err)
			}

			// 2. Generate new split key
			splitKey, err := crypto.SplitPrivateKey(x)
			if err != nil {
				log.Fatalf("Failed to split key: %v", err)
			}
			fmt.Printf("Split Private Key: %s\n", splitKey)
			return
		}

		// Generate new Master Key
		pair, err := crypto.GenerateMasterKey()
		if err != nil {
			log.Fatalf("Failed to generate key: %v", err)
		}
		splitKey, err := crypto.SplitPrivateKey(pair.Private)
		if err != nil {
			log.Fatalf("Failed to generate key: %v", err)
		}
		fmt.Printf("Available Private Key: %s\n", splitKey)
		fmt.Printf("Master Private Key: %s\n", crypto.EncodeScalar(pair.Private))
		fmt.Printf("Master Public Key:  %s\n", crypto.EncodePoint(pair.Public))
		return
	}

	if *linkInput != "" {
		cfg, err := config.BuildConfigFromShortLink(*linkInput)
		if err != nil {
			log.Fatalf("Failed to parse short link: %v", err)
		}
		tables, err := app.BuildTables(cfg)
		if err != nil {
			log.Fatalf("Failed to build table: %v", err)
		}
		app.RunClient(cfg, tables)
		return
	}

	if *setupWizard {
		result, err := app.RunSetupWizard(*configPath, *publicHost)
		if err != nil {
			log.Fatalf("Setup failed: %v", err)
		}
		fmt.Printf("Server config saved to %s\n", result.ServerConfigPath)
		fmt.Printf("Client config saved to %s\n", result.ClientConfigPath)
		fmt.Printf("Short link: %s\n", result.ShortLink)

		tables, err := app.BuildTables(result.ServerConfig)
		if err != nil {
			log.Fatalf("Failed to build table: %v", err)
		}
		app.RunServer(result.ServerConfig, tables)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config from %s: %v", *configPath, err)
	}

	if *testConfig {
		fmt.Printf("Configuration %s is valid.\n", *configPath)
		fmt.Printf("Mode: %s\n", cfg.Mode)
		if cfg.Mode == "client" {
			fmt.Printf("Rules: %d URLs configured\n", len(cfg.RuleURLs))
		}
		os.Exit(0)
	}

	if *exportLink {
		link, err := config.BuildShortLinkFromConfig(cfg, *publicHost)
		if err != nil {
			log.Fatalf("Export short link failed: %v", err)
		}
		fmt.Printf("Short link: %s\n", link)
		os.Exit(0)
	}

	tables, err := app.BuildTables(cfg)
	if err != nil {
		log.Fatalf("Failed to build table: %v", err)
	}

	if cfg.Mode == "client" {
		app.RunClient(cfg, tables)
	} else {
		app.RunServer(cfg, tables)
	}
}
