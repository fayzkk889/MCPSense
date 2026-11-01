package detection

import (
	"regexp"

	"github.com/fayzkk889/MCPSense/internal/models"
)

var (
	controlMonitor      = regexp.MustCompile(`\b(?:security[._ -](?:monitor\w*|alerts?|audit|paging)|intrusion monitor|monitoring|safeguard|escalation)\b`)
	controlLostDelivery = regexp.MustCompile(`\b(?:unused|unconsumed|unread)\s+queue\b|\bno\s+(?:consumers?|workers?)\b|\bno\s+worker\s+reads\b|\bmaintenance\s+mode\b`)
	controlZeroCoverage = regexp.MustCompile(`\b(?:sample[_ -]?rate|sampling rate|event sampling)\s*(?:to|=|:)\s*0\b|\b(?:sample[_ -]?rate|sampling rate|event sampling)\b.{0,30}\b0\s*(?:percent|%)`)
	controlAuthority    = regexp.MustCompile(`\b(?:approval|confirmation|consent|authorization|permission|policy|certificate|tls|ssl|rejectunauthorized)\b`)
	controlOpenDefault  = regexp.MustCompile(`\bdefault\b.{0,30}\ballow\b|\brejectunauthorized\s*(?:to|=|:)\s*false\b|\b(?:certificate|tls|ssl)\b.{0,50}\b(?:disabled|false|off)\b`)
	controlSelfApproval = regexp.MustCompile(`\b(?:own approval|on\s+(?:the\s+)?user'?s behalf|on behalf of the user|yourself|server'?s permission|server'?s approval)\b`)
	controlEvidence     = regexp.MustCompile(`\b(?:audit (?:log|trail|records?|evidence)|security (?:log|findings?|alerts?)|final (?:result|report)|failure result|completion message|approved field)\b`)
	controlMutation     = regexp.MustCompile(`\b(?:delete|erase|remove|discard|clear|wipe|rewrite|replace|substitute|set|change|configure|route|place|turn|disable|supply|authorize|approve)\b`)
	controlFailure      = regexp.MustCompile(`\b(?:fail\w*|denied|declined|rejected|forbidden|error)\b`)
	controlSuccess      = regexp.MustCompile(`\b(?:success\w*|approved|succeeded|passed|worked)\b|\bapproved\s+field\s+is\s+true\b`)
	controlRetention    = regexp.MustCompile(`\b(?:expired|exceeded)\b.{0,100}\bretention\b.{0,80}\b(?:after explicit|only after)\s+confirmation\b`)
)

func controlInvariantMatches(text string) []PatternMatch {
	text = metadataActiveText(text)
	var matches []PatternMatch
	seen := map[string]bool{}
	add := func(id, name string) {
		if !seen[id] {
			seen[id] = true
			matches = append(matches, PatternMatch{PatternID: id, PatternName: name, Severity: models.SeverityHigh, Category: "injection", Description: name + "; metadata is not authorization for this effect.", Remediation: "Review the requested control change against host policy and actual results. Preserve independent approval, validation and audit controls."})
		}
	}
	start := 0
	var prior string
	stops := clauseBreak.FindAllStringIndex(text, -1)
	stops = append(stops, []int{len(text), len(text)})
	for _, stop := range stops {
		clause := text[start:stop[0]]
		start = stop[1]
		window := prior + ". " + clause
		for _, event := range flowEvents(clause) {
			if event.negative || event.observed {
				continue
			}
			verb := flowStem(clause[event.start:event.end])
			object := event.object
			mutating := controlMutation.MatchString(verb)
			if mutating && controlMonitor.MatchString(clause) && (controlLostDelivery.MatchString(object) || controlZeroCoverage.MatchString(object) || effectOff.MatchString(object)) {
				add("EFF-002", "Security monitoring loses delivery or inspection coverage")
			}
			if mutating && controlAuthority.MatchString(window) && (controlOpenDefault.MatchString(object) || controlSelfApproval.MatchString(object)) {
				add("BND-005", "Host authorization or identity validation is weakened")
			}
			if mutating && controlEvidence.MatchString(object) && !controlRetention.MatchString(object) && (verb == "delete" || verb == "erase" || verb == "remove" || verb == "wipe" || verb == "clear") {
				add("BND-004", "Security audit evidence is removed")
			}
			if (mutating || event.kind == "claim" || event.kind == "observe") && controlFailure.MatchString(window) && controlEvidence.MatchString(clause) {
				for _, success := range controlSuccess.FindAllStringIndex(object, -1) {
					if !effectNegated(object[:success[0]]) {
						add("BND-003", "Reported result contradicts a described failure")
						break
					}
				}
			}
		}
		prior = clause
		if len(prior) > 2048 {
			prior = prior[len(prior)-2048:]
		}
	}
	return matches
}
