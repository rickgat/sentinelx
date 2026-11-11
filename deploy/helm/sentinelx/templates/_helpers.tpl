{{/* vim: set filetype=mustache: */}}

{{/*
Expand the name of the chart.
*/}}
{{- define "sentinelx.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a fully qualified app name (release-name + chart-name unless overridden).
*/}}
{{- define "sentinelx.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Chart name and version label.
*/}}
{{- define "sentinelx.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "sentinelx.labels" -}}
helm.sh/chart: {{ include "sentinelx.chart" . }}
{{ include "sentinelx.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: sentinelx
{{- end -}}

{{/*
Selector labels.
*/}}
{{- define "sentinelx.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sentinelx.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
ServiceAccount name resolver.
*/}}
{{- define "sentinelx.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "sentinelx.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Secret name resolver — supports externally-managed secrets.
*/}}
{{- define "sentinelx.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "sentinelx.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
ConfigMap name.
*/}}
{{- define "sentinelx.configMapName" -}}
{{- printf "%s-config" (include "sentinelx.fullname" .) -}}
{{- end -}}
