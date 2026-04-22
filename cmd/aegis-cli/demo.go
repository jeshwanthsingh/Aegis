package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"aegis/internal/api"
	"aegis/internal/config"
	"aegis/internal/policy"
)

func demoCmd(stdout io.Writer, stderr io.Writer, args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: aegis demo <prepare>")
		return 2
	}
	switch args[0] {
	case "prepare":
		return demoPrepare(stdout, stderr, args[1:])
	default:
		fmt.Fprintln(stderr, "usage: aegis demo <prepare>")
		return 2
	}
}

func demoPrepare(stdout io.Writer, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("demo prepare", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "path to config yaml")
	lang := fs.String("lang", "", "language to execute")
	code := fs.String("code", "", "inline code")
	filePath := fs.String("file", "", "path to code file")
	intentFile := fs.String("intent-file", "", "path to an IntentContract JSON file")
	timeoutMs := fs.Int("timeout", 0, "timeout in milliseconds")
	profile := fs.String("profile", "", "compute profile")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if *lang == "" {
		fmt.Fprintln(stderr, "--lang is required")
		return 2
	}
	if (*code == "" && *filePath == "") || (*code != "" && *filePath != "") {
		fmt.Fprintln(stderr, "exactly one of --code or --file is required")
		return 2
	}
	if strings.TrimSpace(*intentFile) == "" {
		fmt.Fprintln(stderr, "--intent-file is required")
		return 2
	}

	source := *code
	if *filePath != "" {
		b, err := os.ReadFile(*filePath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		source = string(b)
	}
	intentRaw, err := os.ReadFile(*intentFile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	repoRoot, err := config.FindRepoRoot("")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	cfg, _, err := loadServeConfig(repoRoot, *configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	pol, err := policy.Load(cfg.Runtime.PolicyPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	preview, err := api.PreviewAdmission(api.ExecuteRequest{
		Lang:      strings.TrimSpace(*lang),
		Code:      source,
		TimeoutMs: *timeoutMs,
		Profile:   strings.TrimSpace(*profile),
		Intent:    json.RawMessage(intentRaw),
	}, pol, cfg.Runtime.AssetsDir, cfg.Runtime.RootfsPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	fmt.Fprintln(stdout, "status=prepared")
	fmt.Fprintf(stdout, "execution_id=%s\n", preview.ExecutionID)
	fmt.Fprintf(stdout, "policy_digest=%s\n", preview.PolicyDigest)
	fmt.Fprintf(stdout, "authority_digest=%s\n", preview.AuthorityDigest)
	approvalMode := strings.TrimSpace(preview.ApprovalMode)
	if approvalMode == "" {
		approvalMode = "none"
	}
	fmt.Fprintf(stdout, "approval_mode=%s\n", approvalMode)
	if len(preview.BrokerActionTypes) > 0 {
		fmt.Fprintf(stdout, "broker_action_types=%s\n", strings.Join(preview.BrokerActionTypes, ","))
	}
	if len(preview.BrokerRepoLabels) > 0 {
		fmt.Fprintf(stdout, "broker_repo_labels=%s\n", strings.Join(preview.BrokerRepoLabels, ","))
	}
	return 0
}
