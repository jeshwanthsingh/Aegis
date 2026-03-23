package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"aegis/internal/models"
)

type executeRequest struct {
	Lang      string `json:"lang"`
	Code      string `json:"code"`
	TimeoutMs int    `json:"timeout_ms,omitempty"`
}

type executeResponse struct {
	Stdout      string `json:"stdout"`
	Stderr      string `json:"stderr"`
	ExitCode    int    `json:"exit_code"`
	DurationMs  int64  `json:"duration_ms"`
	ExecutionID string `json:"execution_id"`
	Error       string `json:"error"`
}

type healthResponse struct {
	Status               string `json:"status"`
	WorkerSlotsAvailable int    `json:"worker_slots_available"`
	WorkerSlotsTotal     int    `json:"worker_slots_total"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "run":
		os.Exit(run(os.Args[2:]))
	case "health":
		os.Exit(health())
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: aegis <run|health>")
	os.Exit(2)
}

func baseURL() string {
	if v := strings.TrimSpace(os.Getenv("AEGIS_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://localhost:8080"
}

func newRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if apiKey := strings.TrimSpace(os.Getenv("AEGIS_API_KEY")); apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	return req, nil
}

func run(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	lang := fs.String("lang", "", "language to execute")
	code := fs.String("code", "", "inline code")
	filePath := fs.String("file", "", "path to code file")
	timeoutMs := fs.Int("timeout", 0, "timeout in milliseconds")
	stream := fs.Bool("stream", false, "stream output as it arrives")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if *lang == "" {
		fmt.Fprintln(os.Stderr, "--lang is required")
		return 2
	}
	if (*code == "" && *filePath == "") || (*code != "" && *filePath != "") {
		fmt.Fprintln(os.Stderr, "exactly one of --code or --file is required")
		return 2
	}

	source := *code
	if *filePath != "" {
		b, err := os.ReadFile(*filePath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		source = string(b)
	}

	payload, err := json.Marshal(executeRequest{Lang: *lang, Code: source, TimeoutMs: *timeoutMs})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	path := "/v1/execute"
	if *stream {
		path = "/v1/execute/stream"
	}
	req, err := newRequest(http.MethodPost, baseURL()+path, bytes.NewReader(payload))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()

	if *stream {
		return consumeStream(resp)
	}
	return consumeSingle(resp)
}

func consumeSingle(resp *http.Response) int {
	var out executeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	if out.Stdout != "" {
		fmt.Print(out.Stdout)
	}
	if out.Stderr != "" {
		for _, line := range strings.Split(strings.TrimRight(out.Stderr, "\n"), "\n") {
			if line == "" {
				continue
			}
			fmt.Printf("[stderr] %s\n", line)
		}
	}

	if out.Error != "" {
		if out.Error == "timeout" {
			fmt.Fprintln(os.Stderr, "execution timed out")
		} else {
			fmt.Fprintln(os.Stderr, out.Error)
		}
		fmt.Printf("[done in %dms]\n", out.DurationMs)
		return 1
	}

	if out.ExitCode != 0 {
		fmt.Printf("[exit code %d]\n", out.ExitCode)
		fmt.Printf("[done in %dms]\n", out.DurationMs)
		return 1
	}

	fmt.Printf("[done in %dms]\n", out.DurationMs)
	return 0
}

func consumeStream(resp *http.Response) int {
	if !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		return consumeSingle(resp)
	}

	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		var chunk models.GuestChunk
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		switch chunk.Type {
		case "stdout":
			fmt.Print(chunk.Chunk)
		case "stderr":
			for _, line := range strings.Split(strings.TrimRight(chunk.Chunk, "\n"), "\n") {
				if line == "" {
					continue
				}
				fmt.Printf("[stderr] %s\n", line)
			}
		case "error":
			if chunk.Error == "timeout" {
				fmt.Fprintln(os.Stderr, "execution timed out")
			} else {
				fmt.Fprintln(os.Stderr, chunk.Error)
			}
			return 1
		case "done":
			if chunk.ExitCode != 0 {
				fmt.Printf("[exit code %d]\n", chunk.ExitCode)
				fmt.Printf("[done in %dms]\n", chunk.DurationMs)
				return 1
			}
			fmt.Printf("[done in %dms]\n", chunk.DurationMs)
			return 0
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "stream ended unexpectedly")
	return 1
}

func health() int {
	req, err := newRequest(http.MethodGet, baseURL()+"/health", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()

	var out healthResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	fmt.Printf("status: %s\n", out.Status)
	fmt.Printf("workers: %d/%d available\n", out.WorkerSlotsAvailable, out.WorkerSlotsTotal)
	return 0
}