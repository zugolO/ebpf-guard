// Package correlator provides DGA detection via N-gram character language model.
// Modern DGA algorithms deliberately produce domains with normal Shannon entropy,
// defeating entropy-only detectors. This model captures character-level n-gram
// statistics of legitimate domain names and scores each domain against them:
// unusual character sequences (typical of algorithm-generated names) yield a
// high score close to 1.0, while normal-looking names score close to 0.0.
package correlator

import (
	"math"
	"strings"
	"sync"
)

// ngramCharsetSize is the size of the character alphabet used by the model.
// Slots: a–z (0–25), 0–9 (26–35), '-' (36).
const ngramCharsetSize = 37

// legitimateDomainCorpus is a compact embedded training corpus of representative
// second-level domain name components drawn from major web properties, CDN and
// infrastructure patterns, and common English words used in domain names.
// TLDs are excluded; only SLD-level tokens are included, all lower-case.
// Bigram statistics are derived from this corpus at init time with Laplace smoothing.
const legitimateDomainCorpus = `` +
	// ── Top web properties ─────────────────────────────────────────────────
	`google youtube facebook amazon apple microsoft netflix twitter instagram ` +
	`linkedin github stackoverflow wordpress cloudflare wikipedia reddit discord ` +
	`dropbox twitch spotify salesforce shopify paypal adobe atlassian slack zoom ` +
	`tumblr medium azure gcloud heroku netlify vercel supabase railway render ` +
	`planetscale neon oracle ibm intel nvidia amd qualcomm broadcom samsung sony ` +
	// ── CDN and infrastructure ─────────────────────────────────────────────
	`akamai fastly jsdelivr stackpath bunnycdn cloudfront maxcdn edgecast limelight ` +
	`cdn1 cdn2 static1 static2 img1 img2 assets1 assets2 media1 media2 ` +
	`eu-west us-east us-west asia-pacific ap-southeast ap-northeast ` +
	`primary secondary backup failover replica master slave node1 node2 ` +
	// ── Service and app keywords ───────────────────────────────────────────
	`login portal admin dashboard control panel secure private api gateway proxy ` +
	`auth oauth sso ldap saml oidc token secret key certificate ssl tls ` +
	`mail smtp imap pop3 webmail relay sendgrid mailgun postmark sparkpost ` +
	`server hosting database storage cache redis memcached elastic search ` +
	`static media assets images photos videos audio podcast content upload ` +
	`news feed blog post article release update patch version changelog docs ` +
	`shop store market place catalog inventory shipping billing subscription ` +
	`support helpdesk tickets forum community social network profile settings ` +
	`analytics metrics monitor health status check ping test staging dev prod ` +
	`cloud compute platform service solution system software hardware infra ` +
	`mobile web desktop enterprise business professional personal home office ` +
	`search engine index crawler automation pipeline workflow scheduler ` +
	`payment gateway banking finance insurance investment capital account ` +
	`health medical research laboratory science engineering technology ` +
	`education training learning certificate professional developer ` +
	`travel booking hotel airline reservation transport logistics fleet ` +
	`gaming entertainment streaming broadcast video music creative studio ` +
	`legal compliance governance policy regulation audit report dashboard ` +
	`internal external public private vpn tunnel bridge router switch ` +
	// ── English word fragments common in SLDs ─────────────────────────────
	`information technology computer science management application development ` +
	`operations security infrastructure performance reliability availability ` +
	`communication collaboration workspace project agile release cycle ` +
	`community creative design brand marketing digital transformation ` +
	`professional services consulting enterprise architecture integration ` +
	`global local regional national international standard framework ` +
	`protection detection prevention response analysis intelligence threat ` +
	`access control identity management authentication authorization policy `

// NgramDGADetector scores domain names using a character bigram language model.
// Domains whose character sequences are improbable under the model (i.e. look
// random) receive a high score; legitimate-looking domains receive a low score.
type NgramDGADetector struct {
	// bigramLP[prev][curr] = ln P(curr | prev), row-normalised with Laplace smoothing.
	bigramLP  [ngramCharsetSize][ngramCharsetSize]float32
	threshold float64
}

var (
	defaultNgramDetector     *NgramDGADetector
	defaultNgramDetectorOnce sync.Once
)

// DefaultNgramDGADetector returns the singleton detector initialised with the
// embedded corpus and a default DGA-score threshold of 0.70.
func DefaultNgramDGADetector() *NgramDGADetector {
	defaultNgramDetectorOnce.Do(func() {
		defaultNgramDetector = NewNgramDGADetector(0.70)
	})
	return defaultNgramDetector
}

// NewNgramDGADetector creates a detector trained on the embedded corpus.
// threshold ∈ [0,1]: Score() values at or above this are classified as DGA.
func NewNgramDGADetector(threshold float64) *NgramDGADetector {
	d := &NgramDGADetector{threshold: threshold}
	d.train()
	return d
}

// train computes row-normalised ln-probabilities from the embedded corpus.
func (d *NgramDGADetector) train() {
	var counts [ngramCharsetSize][ngramCharsetSize]float32

	// Laplace prior of 1 ensures no -Inf log-prob for unseen bigrams.
	for i := range counts {
		for j := range counts[i] {
			counts[i][j] = 1.0
		}
	}

	// Tally bigrams from every token in the training corpus.
	for _, tok := range strings.Fields(legitimateDomainCorpus) {
		tok = strings.ToLower(tok)
		for i := 1; i < len(tok); i++ {
			pi := ngramCharIdx(tok[i-1])
			ci := ngramCharIdx(tok[i])
			if pi >= 0 && ci >= 0 {
				counts[pi][ci]++
			}
		}
	}

	// Convert to ln-probabilities (row-normalised).
	for i := 0; i < ngramCharsetSize; i++ {
		var total float32
		for j := 0; j < ngramCharsetSize; j++ {
			total += counts[i][j]
		}
		for j := 0; j < ngramCharsetSize; j++ {
			d.bigramLP[i][j] = float32(math.Log(float64(counts[i][j] / total)))
		}
	}
}

// Score returns a value in [0, 1] indicating how likely a domain is DGA-generated.
// Only the second-level domain (SLD) is scored; subdomains and TLDs are ignored.
//
// The score is derived from the average ln-probability of successive character
// bigrams. Domains with unusual character sequences score close to 1.0; normal-
// looking domains score close to 0.0.
//
// Sigmoid offset −3.5: the decision boundary sits at an average ln-probability
// of −3.5, which empirically separates legitimate from DGA domains well when the
// model is trained on the embedded corpus.
func (d *NgramDGADetector) Score(domain string) float64 {
	sld := ngramExtractSLD(domain)
	if len(sld) < 4 {
		return 0 // too short to score reliably
	}

	var lnProbSum float64
	n := 0
	for i := 1; i < len(sld); i++ {
		pi := ngramCharIdx(sld[i-1])
		ci := ngramCharIdx(sld[i])
		if pi < 0 || ci < 0 {
			continue
		}
		lnProbSum += float64(d.bigramLP[pi][ci])
		n++
	}
	if n == 0 {
		return 0
	}

	avgLnP := lnProbSum / float64(n)
	// score = sigmoid(−(avgLnP + 3.5))
	// avgLnP ≈ −1.5 (common bigrams) → score ≈ 0.12 (legitimate)
	// avgLnP ≈ −3.5 (neutral)        → score  = 0.50
	// avgLnP ≈ −6.0 (rare bigrams)   → score ≈ 0.92 (DGA)
	return 1.0 / (1.0 + math.Exp(avgLnP+3.5))
}

// IsDGA returns true when the domain's N-gram score is at or above the detector
// threshold. Short or non-qualifying domains always return false.
func (d *NgramDGADetector) IsDGA(domain string) bool {
	return d.Score(domain) >= d.threshold
}

// Score is a package-level convenience wrapper that uses the singleton detector.
func Score(domain string) float64 {
	return DefaultNgramDGADetector().Score(domain)
}

// ngramCharIdx maps a byte to its position in the model's character alphabet.
// Returns −1 for characters outside the alphabet (treated as separators).
func ngramCharIdx(c byte) int {
	switch {
	case c >= 'a' && c <= 'z':
		return int(c - 'a')
	case c >= '0' && c <= '9':
		return int(c-'0') + 26
	case c == '-':
		return 36
	default:
		return -1
	}
}

// ngramExtractSLD returns the second-level domain from a fully qualified domain name,
// lower-cased and stripped of trailing dots.
// Examples:
//
//	"www.google.com"           → "google"
//	"api.service.example.com"  → "example"
//	"xkjlmzab123.io"           → "xkjlmzab123"
//	"localhost"                → "localhost"
func ngramExtractSLD(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}
	return parts[len(parts)-2]
}
