{{/*
Expand the name of the chart.
*/}}
{{- define "ebpf-guard.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "ebpf-guard.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart label.
*/}}
{{- define "ebpf-guard.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "ebpf-guard.labels" -}}
helm.sh/chart: {{ include "ebpf-guard.chart" . }}
{{ include "ebpf-guard.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "ebpf-guard.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ebpf-guard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "ebpf-guard.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ebpf-guard.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Container image.
*/}}
{{- define "ebpf-guard.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}

{{/*
Release namespace (supports namespaceCreate=false with pre-existing ns).
*/}}
{{- define "ebpf-guard.namespace" -}}
{{- .Release.Namespace }}
{{- end }}

{{/*
GOMEMLIMIT in bytes, computed as gomemlimit.percent (default 90) of
.Values.resources.limits.memory. Gives the Go runtime a soft memory limit so GC
keeps RSS under the cgroup limit. Returns an empty string when no memory limit
is configured, so callers can skip setting the env var entirely.

Supported quantity suffixes: Ti/Gi/Mi/Ki (binary) and G/M/k (SI);
a bare number is treated as bytes.
*/}}
{{- define "ebpf-guard.gomemlimit" -}}
{{- $mem := .Values.resources.limits.memory | default "" | toString -}}
{{- if ne $mem "" -}}
{{- $bytes := 0.0 -}}
{{- if hasSuffix "Gi" $mem -}}{{- $bytes = mulf (trimSuffix "Gi" $mem | float64) 1073741824.0 -}}
{{- else if hasSuffix "Mi" $mem -}}{{- $bytes = mulf (trimSuffix "Mi" $mem | float64) 1048576.0 -}}
{{- else if hasSuffix "Ki" $mem -}}{{- $bytes = mulf (trimSuffix "Ki" $mem | float64) 1024.0 -}}
{{- else if hasSuffix "Ti" $mem -}}{{- $bytes = mulf (trimSuffix "Ti" $mem | float64) 1099511627776.0 -}}
{{- else if hasSuffix "G" $mem -}}{{- $bytes = mulf (trimSuffix "G" $mem | float64) 1000000000.0 -}}
{{- else if hasSuffix "M" $mem -}}{{- $bytes = mulf (trimSuffix "M" $mem | float64) 1000000.0 -}}
{{- else if hasSuffix "k" $mem -}}{{- $bytes = mulf (trimSuffix "k" $mem | float64) 1000.0 -}}
{{- else -}}{{- $bytes = $mem | float64 -}}
{{- end -}}
{{- $pct := .Values.gomemlimit.percent | default 90 -}}
{{- printf "%d" (mulf $bytes (divf ($pct | float64) 100.0) | int64) -}}
{{- end -}}
{{- end }}
