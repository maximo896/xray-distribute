package main

import (
	"encoding/json"
	"fmt"

	"github.com/xray-distribute/internal/model"
	"github.com/xray-distribute/internal/trafficdb"
)

func buildOOBVulnerability(interaction model.OOBInteraction, match *trafficdb.Match) *model.Vulnerability {
	if match == nil {
		return nil
	}

	detail := map[string]interface{}{
		"oob_protocol":       interaction.Protocol,
		"oob_full_id":        interaction.FullID,
		"oob_request":        interaction.RawRequest,
		"oob_response":       interaction.RawResponse,
		"remote_address":     interaction.RemoteAddress,
		"matched_source":     match.Source,
		"matched_id":         match.ID,
		"matched_method":     match.Method,
		"matched_url":        match.URL,
		"matched_raw":        match.Raw,
		"matched_created_at": match.CreatedAt,
	}
	detailJSON, _ := json.Marshal(detail)

	return &model.Vulnerability{
		ID:          fmt.Sprintf("oob-%s-%s-%d", interaction.Protocol, interaction.FullID, interaction.Timestamp.UnixNano()),
		Plugin:      "interactsh",
		URL:         match.URL,
		VulnClass:   "oob-interaction",
		Severity:    "medium",
		Title:       fmt.Sprintf("OOB interaction received (%s)", interaction.Protocol),
		Description: fmt.Sprintf("Remote address: %s; matched %s request: %s %s", interaction.RemoteAddress, match.Source, match.Method, match.URL),
		Request:     match.Raw,
		Response:    interaction.RawResponse,
		Detail:      string(detailJSON),
		CreatedAt:   interaction.Timestamp,
	}
}
