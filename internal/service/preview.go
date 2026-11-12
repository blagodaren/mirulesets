package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/blagodaren/mirulesets/internal/fetcher"
	"github.com/blagodaren/mirulesets/internal/model"
)

const previewLineLimit = 200

type SourcePreview struct {
	RuleCount int      `json:"ruleCount"`
	SizeBytes int      `json:"sizeBytes"`
	Format    string   `json:"format"`
	Behavior  string   `json:"behavior"`
	Lines     []string `json:"lines"`
	Truncated bool     `json:"truncated"`
}

func (s *Service) PreviewSource(ctx context.Context, rawURL, format, behavior string) (SourcePreview, error) {
	var result SourcePreview
	rawURL = strings.TrimSpace(rawURL)
	if len(rawURL) > 8192 {
		return result, fmt.Errorf("слишком длинный адрес или название источника")
	}
	if err := fetcher.ValidateURL(rawURL); err != nil {
		return result, err
	}
	if !slices.Contains([]string{"auto", "yaml", "text", "mrs"}, format) {
		return result, fmt.Errorf("неизвестный формат источника")
	}
	if !slices.Contains([]string{"domain", "ipcidr", "classical"}, behavior) {
		return result, fmt.Errorf("неизвестный behavior источника")
	}
	lines, _, metadata, err := s.loadSource(ctx, model.Source{URL: rawURL, Format: format, Behavior: behavior})
	if err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	result = SourcePreview{RuleCount: len(lines), SizeBytes: metadata.sizeBytes, Format: metadata.format, Behavior: behavior, Lines: lines, Truncated: len(lines) > previewLineLimit}
	if result.Truncated {
		result.Lines = lines[:previewLineLimit]
	}
	return result, nil
}

// Keep auto detection identical to rules.ParseSource while returning its format
// together with the source bytes used by both builds and previews.
func sourceFormat(data []byte, format string) string {
	if format != "auto" {
		return format
	}
	if len(data) >= 4 && bytes.Equal(data[:4], []byte{0x28, 0xb5, 0x2f, 0xfd}) {
		return "mrs"
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte{'{'}) {
		var envelope struct {
			Version json.RawMessage `json:"version"`
			Rules   json.RawMessage `json:"rules"`
		}
		if json.Unmarshal(trimmed, &envelope) == nil && len(envelope.Version) > 0 && len(envelope.Rules) > 0 {
			return "singbox"
		}
		return "yaml"
	}
	for len(data) > 0 {
		line, rest, found := bytes.Cut(data, []byte{'\n'})
		line = bytes.TrimSpace(line)
		if bytes.HasPrefix(line, []byte("[Adblock")) || bytes.HasPrefix(line, []byte("||")) || bytes.HasPrefix(line, []byte("@@||")) {
			return "adblock"
		}
		if fields := bytes.Fields(line); len(fields) >= 2 {
			if _, err := netip.ParseAddr(string(fields[0])); err == nil {
				return "hosts"
			}
		}
		if bytes.HasPrefix(line, []byte("payload:")) || bytes.HasPrefix(line, []byte("rules:")) {
			return "yaml"
		}
		if !found {
			break
		}
		data = rest
	}
	return "text"
}
