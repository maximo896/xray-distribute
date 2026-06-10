package main

import (
	"encoding/json"
	"fmt"

	"github.com/xray-distribute/internal/model"
	"github.com/xray-distribute/internal/trafficdb"
)

func buildOOBVulnerability(interaction model.OOBInteraction, match *trafficdb.Match) *model.Vulnerability {
	detail := map[string]interface{}{
		"oob_protocol":   interaction.Protocol,
		"oob_full_id":    interaction.FullID,
		"oob_request":    interaction.RawRequest,
		"oob_response":   interaction.RawResponse,
		"remote_address": interaction.RemoteAddress,
	}

	vuln := &model.Vulnerability{
		ID:          fmt.Sprintf("oob-%s-%s-%d", interaction.Protocol, interaction.FullID, interaction.Timestamp.UnixNano()),
		Plugin:      "interactsh",
		URL:         interaction.FullID,
		VulnClass:   "oob-interaction",
		Severity:    "medium",
		Title:       fmt.Sprintf("OOB interaction received (%s)", interaction.Protocol),
		Description: fmt.Sprintf("Remote address: %s", interaction.RemoteAddress),
		Request:     interaction.RawRequest,
		Response:    interaction.RawResponse,
		CreatedAt:   interaction.Timestamp,
	}

	if match != nil {
		vuln.URL = match.URL
		vuln.Description = fmt.Sprintf("Remote address: %s; matched %s request: %s %s", interaction.RemoteAddress, match.Source, match.Method, match.URL)
		vuln.Request = match.Raw
		detail["matched_source"] = match.Source
		detail["matched_id"] = match.ID
		detail["matched_method"] = match.Method
		detail["matched_url"] = match.URL
		detail["matched_raw"] = match.Raw
		detail["matched_created_at"] = match.CreatedAt
	}

	detailJSON, _ := json.Marshal(detail)
	vuln.Detail = string(detailJSON)
	return vuln
}
