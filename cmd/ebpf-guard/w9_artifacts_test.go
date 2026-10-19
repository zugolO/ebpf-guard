package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readRepo(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile("../../" + rel)
	require.NoError(t, err)
	return string(b)
}

// 9.1 / Д15 (волна 9): два артефакта. Сторож по исходникам сборки: образ по умолчанию — core
// (GO_TAGS пуст, тега rego в Dockerfile нет), full — отдельная цель и отдельный тег, релиз
// собирает обе, чарт по умолчанию тянет core и не включает Rego.
func TestW9_D15_TwoArtifacts(t *testing.T) {
	df := readRepo(t, "Dockerfile")
	assert.Regexp(t, regexp.MustCompile(`(?m)^ARG GO_TAGS=""$`), df, "умолчание Dockerfile — core (GO_TAGS пуст)")
	assert.NotRegexp(t, regexp.MustCompile(`go build[^\n]*-tags rego`), df, "тег rego зашит в Dockerfile — core невозможен")
	assert.Contains(t, df, `${GO_TAGS:+-tags "$GO_TAGS"}`)

	mk := readRepo(t, "Makefile")
	assert.Regexp(t, regexp.MustCompile(`(?m)^docker:\n(?:.*\n)*?\s+docker build -t ebpf-guard:latest \.$`), mk, "make docker — core")
	assert.Contains(t, mk, "docker build --build-arg GO_TAGS=rego -t ebpf-guard:latest-full .", "make docker-full")
	assert.Contains(t, mk, "docker-full", "docker-full в .PHONY")

	rel := readRepo(t, ".github/workflows/release.yml")
	assert.Contains(t, rel, `suffix: "-full"`)
	assert.Contains(t, rel, "go_tags: rego")
	assert.Contains(t, rel, "GO_TAGS=${{ matrix.go_tags }}")

	vals := readRepo(t, "deploy/helm/ebpf-guard/values.yaml")
	assert.Regexp(t, regexp.MustCompile(`(?m)^  variant: core$`), vals, "умолчание чарта — core")
	assert.Regexp(t, regexp.MustCompile(`(?s)  policy:\n    rego:\n      enabled: false`), vals, "Rego в чарте по умолчанию выключен")

	helper := readRepo(t, "deploy/helm/ebpf-guard/templates/_helpers.tpl")
	assert.Contains(t, helper, `-full`)
	cm := readRepo(t, "deploy/helm/ebpf-guard/templates/configmap.yaml")
	assert.Contains(t, cm, "requires image.variant=full", "core-образ с policy.rego.enabled=true не отрисовывается")
	assert.True(t, strings.Contains(cm, "policy:") && strings.Contains(cm, "sequence:"))
}
