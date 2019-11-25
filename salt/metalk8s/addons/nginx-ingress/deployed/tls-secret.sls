#!jinja | metalk8s_kubernetes

apiVersion: v1
kind: Secret
metadata:
  name: ingress-workload-plane-default-certificate
  namespace: metalk8s-ingress
type: Opaque
data:
  tls.crt: "{{
    salt['hashutil.base64_encodefile'](
        '/etc/metalk8s/pki/nginx-ingress/workload-plane-server.crt'
    ) | replace('\n', '')
  }}"
  tls.key: "{{
    salt['hashutil.base64_encodefile'](
        '/etc/metalk8s/pki/nginx-ingress/workload-plane-server.key'
    ) | replace('\n', '')
  }}"
