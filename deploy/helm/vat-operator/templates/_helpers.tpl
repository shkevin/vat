{{- define "vat-operator.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride -}}
{{- end -}}

{{- define "vat-operator.operatorImage" -}}
{{- printf "%s:%s" .Values.operator.image.repository .Values.operator.image.tag -}}
{{- end -}}

{{- define "vat-operator.scannerImage" -}}
{{- printf "%s:%s" .Values.scanner.image.repository .Values.scanner.image.tag -}}
{{- end -}}
