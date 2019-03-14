#  run_certs
#  run_kubeconfig
#  run_control_plane
#  run_etcd
#  run_mark_control_plane
#  install_addons
#  install_calico

Bootstrap node:
  salt.state:
    - tgt: bootstrap
    - saltenv: metalk8s-2.0
    - sls:
      - metalk8s.bootstrap.certificates
