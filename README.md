# Caligula
[![](https://images.microbadger.com/badges/version/keyparty/caligula.svg)](https://hub.docker.com/r/keyparty/caligula "caligula")
[![](https://images.microbadger.com/badges/image/keyparty/caligula.svg)](https://microbadger.com/images/keyparty/caligula "caligula")

##Usage

```
Usage of ./caligula:
  -client
    	Client PKI management Active
  -client-pki-path string
    	PKI secret backend issue path (e.g., '/pki/issue/<role name>')
  -client-pki-ttl string
    	certificate time to live (default "60s")
  -cluster-domain string
    	Kubernetes cluster domain (default "cluster.local")
  -hostname string
    	hostname as defined by pod.spec.hostname
  -ip string
    	IP address as defined by pod.status.podIP
  -name string
    	name as defined by pod.metadata.name
  -namespace string
    	namespace as defined by pod.metadata.namespace (default "default")
  -server-pki-path string
    	PKI secret backend issue path (e.g., '/pki/issue/<role name>')
  -server-pki-ttl string
    	server certificate time to live (default "60s")
  -service-name string
    	Kubernetes service name that resolves to this Pod
  -subdomain string
    	subdomain as defined by pod.spec.subdomain
  -vault-addr string
    	Vault service address (default "https://vault:8200")
  -write-cert-path string
    	Directory path to write certificates to (e.g., '/var/run/secrets/keyparty')
```
