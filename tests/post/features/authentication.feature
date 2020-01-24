@post @local @ci @authentication
Feature: Authentication is up and running
    Scenario: List Pods
        Given the Kubernetes API is available
        Then the 'pods' list should not be empty in the 'metalk8s-auth' namespace

    Scenario: Expected Pods
        Given the Kubernetes API is available
        And pods with label 'release=nginx-ingress-control-plane' are 'Ready'
        Then we have 2 running pod labeled 'app.kubernetes.io/name=dex' in namespace 'metalk8s-auth' on node 'bootstrap'

    Scenario: Reach the OpenID Config
        Given the Kubernetes API is available
        And the control-plane Ingress pod is Ready
        And the control-plane Ingress container is Ready
        And pods with label 'app.kubernetes.io/name=dex' are 'Ready'
        Then we can reach the OIDC openID configuration

    Scenario: Access HTTPS service
        Given the Kubernetes API is available
        And the control-plane Ingress pod is Ready
        And the control-plane Ingress container is Ready
        And pods with label 'app.kubernetes.io/name=dex' are 'Ready'
        When we perform a request on '/oidc/' with port '8443' on control-plane IP
        Then the server returns '404' with message '404 page not found'

    Scenario: Login to Dex using incorrect email
        Given the Kubernetes API is available
        And the control-plane Ingress pod is Ready
        And the control-plane Ingress container is Ready
        And pods with label 'app.kubernetes.io/name=dex' are 'Ready'
        When we login to Dex as 'admin@metalk8s.com' using password 'password'
        Then authentication fails with login error

    Scenario: Login to Dex using correct email and password
        Given the Kubernetes API is available
        And the control-plane Ingress pod is Ready
        And the control-plane Ingress container is Ready
        And pods with label 'app.kubernetes.io/name=dex' are 'Ready'
        When we login to Dex as 'admin@metalk8s.invalid' using password 'password'
        Then the server returns '303' with an ID token
