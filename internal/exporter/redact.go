package exporter

import (
	"errors"
	"net/url"
)

// redactURLError removes the URL from a *url.Error to prevent secret tokens
// (Telegram bot tokens, Discord/Teams webhook secrets) from leaking into logs.
// Returns the original error with the URL field replaced by "[redacted]".
func redactURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		urlErr.URL = "[redacted]"
	}
	return err
}
