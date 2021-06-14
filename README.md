# es-change-passwords

This tool can be user for half-automated elasticsearch passwords management.

## Binary

### Arguments

#### Example

`es-change-passwords -endpoint "https://127.0.0.1:9200" -config=test/config.yml -insecure=true -tls-cert=test/tls.crt -tls-key=test/tls.key -tls-ca=test/ca.crt`

#### Reference

| argument  | type   | comment                         | default                |
|-----------|--------|---------------------------------|------------------------|
| -endpoint | string | Elasticsearch http(s) port      | https://127.0.0.1:9200 |
| -config   | string | path to configuration file      | config.yml             |
| -insecure | bool   | Skip tls checks?                | false                  |
| -tls-cert | string | Path to client .pem certificate |                        |
| -tls-key  | string | Path to client .pem private key |                        |
| -tls-ca   | string | Path to CA .pem certificate     |                        |

### Configuration file

#### Example

```yaml
passwords: []
#  - username: elastic
#    password: newChangeMe
#    old_password: changeme
#  - username: kibana
#    password: newChangeMe
```

#### Reference

- **passwords**: list
    - **username**: string, username to proceed
  - **password**: string, password to set
    - **old_password**: string, used only for `elastic` user

## Helm chart

### usage

```shell
helm -n logging upgrade --install es-passwords .helm/es-change-passwords \
--set endpoint="https://es-headless:9200" \
--set certs.secretName="es-http" \
--set certs.mount=true \
--set fullnameOverride="passwords"
```

### `values.yaml` reference

- **certs**:
    - **mount**: boolean, is secret mount required
    - **secretName**: string, secret name to mount
    - **keyCA**: string, key in secret with CA certificate
    - **keyCert**: string, key in secret with client tls certificate
    - **keyKey**: string, key in secret with client tls key
- **endpoint**: string, elasticsearch http(s) endpoint
- **passwords**: list
    - **username**: string, username to proceed
    - **password**: string, password to set
        - **old_password**: string, used only for `elastic` user
- **image**: string, image to use
- **imagePullSecrets**: list, see [Specifying imagePullSecrets on a Pod](https://kubernetes.io/docs/concepts/containers/images/#specifying-imagepullsecrets-on-a-pod)
- **nameOverride**: string, partial override
- **fullnameOverride**: string, full override
- **resources**: object, see [Managing Resources for Containers](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#requests-and-limits)
- **nodeSelector**: object, see [Assigning Pods to Nodes : nodeSelector](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector)
- **tolerations**: list, see [Taints and Tolerations](https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/)
- **affinity**: object, see [Assigning Pods to Nodes : Affinity and anti-affinity](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#affinity-and-anti-affinity)
