package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func runStatus(rawURL, basicAuth, token string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid statusURL: %w", err)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/metrics"
	}

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("X-Ngrok-Admin-Token", token)
	}
	if basicAuth != "" {
		parts := strings.SplitN(basicAuth, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("statusAuth must be user:password")
		}
		req.SetBasicAuth(parts[0], parts[1])
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("status endpoint returned %s", resp.Status)
	}

	var payload interface{}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	out, _ := json.MarshalIndent(payload, "", "  ")
	fmt.Println(string(out))
	return nil
}
