{{/*
Expand the name of the chart.
*/}}
{{- define "pbs-cloud.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "pbs-cloud.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "pbs-cloud.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "pbs-cloud.labels" -}}
helm.sh/chart: {{ include "pbs-cloud.chart" . }}
{{ include "pbs-cloud.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "pbs-cloud.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pbs-cloud.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "pbs-cloud.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "pbs-cloud.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Return the S3 credentials secret name
*/}}
{{- define "pbs-cloud.s3SecretName" -}}
{{- if .Values.storage.s3.existingSecret }}
{{- .Values.storage.s3.existingSecret }}
{{- else }}
{{- include "pbs-cloud.fullname" . }}-s3
{{- end }}
{{- end }}

{{/*
Return the TLS secret name
*/}}
{{- define "pbs-cloud.tlsSecretName" -}}
{{- if .Values.tls.existingSecret }}
{{- .Values.tls.existingSecret }}
{{- else }}
{{- include "pbs-cloud.fullname" . }}-tls
{{- end }}
{{- end }}

{{/*
Return the persistence PVC name
*/}}
{{- define "pbs-cloud.persistencePvcName" -}}
{{- if .Values.persistence.existingClaim }}
{{- .Values.persistence.existingClaim }}
{{- else }}
{{- include "pbs-cloud.fullname" . }}-data
{{- end }}
{{- end }}

{{/*
Return the storage PVC name
*/}}
{{- define "pbs-cloud.storagePvcName" -}}
{{- include "pbs-cloud.fullname" . }}-storage
{{- end }}
