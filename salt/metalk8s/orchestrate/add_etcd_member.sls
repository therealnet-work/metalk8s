{# Should be run by the orchestrator runner #}
# This state cannot run on a minion since it depends on etcd3 python lib
# which is only available by default on the salt-master.

{%- set node_name = pillar.orchestrate.node_name %}
{%- set version = pillar.metalk8s.nodes[node_name].version %}

{%- set node_ip = salt.saltutil.runner(
    'mine.get',
     tgt=node_name,
     fun='control_plane_ip')[node_name]
 %}

{%- set peer_url = 'https://' ~ node_ip ~ ':2380' %}

Refresh and check pillar before etcd deployment:
  salt.function:
    - name: metalk8s.check_pillar_keys
    - tgt: {{ node_name }}
    - kwarg:
        keys:
          - metalk8s.endpoints.salt-master.ip
          - metalk8s.endpoints.repositories.ip
          - metalk8s.endpoints.repositories.ports.http
        # We cannot raise when using `salt.function` as we need to return
        # `False` to have a failed state
        # https://github.com/saltstack/salt/issues/55503
        raise_error: False
    - retry:
        attempts: 5

Pre-install node for etcd:
  salt.state:
    - tgt: {{ node_name }}
    - saltenv: metalk8s-{{ version }}
    - sls:
      - metalk8s.roles.internal.node-without-calico
    - pillar:
        metalk8s:
          skip_apiserver_proxy_healthcheck: True
    - require:
      - salt: Refresh and check pillar before etcd deployment

Prepare etcd dependencies:
  salt.state:
    - tgt: {{ node_name }}
    - saltenv: metalk8s-{{ version }}
    - sls:
      - metalk8s.kubernetes.etcd.prepared
    - require:
      - salt: Pre-install node for etcd

Register host as part of etcd cluster:
  metalk8s_etcd.member_present:
    - name: {{ node_name }}
    - peer_urls:
      - {{ peer_url }}
    - require:
      - salt: Prepare etcd dependencies

Install etcd:
  salt.state:
    - tgt: {{ node_name }}
    - saltenv: metalk8s-{{ version }}
    - sls:
      - metalk8s.kubernetes.etcd.installed
    - pillar:
        metalk8s:
          skip_etcd_healthcheck: True
    - require:
      - salt: Register host as part of etcd cluster
