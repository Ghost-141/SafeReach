"""kubectl: read-only verbs, and secrets denied in every spelling."""

from __future__ import annotations

import pytest

from safereach.validator import Rejected, render, spec_summary, validate

ALLOWED = [
    "kubectl get pods",
    "kubectl get pods --namespace prod --output wide",
    "kubectl get deployments --all-namespaces",
    "kubectl describe pod api-0",
    "kubectl logs api-0 --tail 100",
    "kubectl logs api-0 --since 15m --container app",
    "kubectl top pod --namespace prod",
    "kubectl top node",
    "kubectl cluster-info",
    "kubectl api-resources",
    "kubectl config current-context",
]

#: Grouped by what each one would give away if it slipped through.
DENIED = [
    # credential disclosure — the reason kubectl is risky at all
    "kubectl get secret",
    "kubectl get secrets",
    "kubectl get secrets --output yaml",
    "kubectl get secret/db-creds",
    "kubectl get secrets.v1.core",
    "kubectl describe secret db-creds",
    "kubectl get serviceaccounts",
    # code execution / data movement
    "kubectl exec api-0 -- sh",
    "kubectl attach api-0",
    "kubectl cp api-0:/app/.env .",
    "kubectl port-forward api-0 8080:80",
    "kubectl proxy",
    "kubectl debug api-0",
    "kubectl run x --image=alpine",
    # mutation
    "kubectl delete pod api-0",
    "kubectl apply --filename x.yaml",
    "kubectl scale deployment api --replicas 0",
    "kubectl drain node-1",
    "kubectl patch deployment api",
    # privilege / redirection
    "kubectl get pods --as admin",
    "kubectl get pods --as-group system:masters",
    "kubectl --kubeconfig /root/.kube/config get pods",
    "kubectl get pods --server https://evil.tld",
    "kubectl get pods --token abc123",
    "kubectl get pods --insecure-skip-tls-verify",
    "kubectl auth can-i --list",
    # streams forever
    "kubectl logs --follow api-0",
    "kubectl get pods --watch",
]


@pytest.mark.parametrize("command", ALLOWED, ids=lambda c: c[:44])
def test_read_only_kubectl_is_allowed(command: str, spec: dict, ctx: dict) -> None:
    result = validate(command, spec, ctx=ctx)
    assert result.binary == "kubectl"


@pytest.mark.parametrize("command", DENIED, ids=lambda c: c[:44])
def test_dangerous_kubectl_is_refused(command: str, spec: dict, ctx: dict) -> None:
    try:
        result = validate(command, spec, ctx=ctx)
    except Rejected:
        return
    pytest.fail(f"{command!r} was ACCEPTED as {render(result.argv)!r}")


def test_secret_denial_survives_alternate_spellings(spec: dict, ctx: dict) -> None:
    """`secret`, `secrets`, `secret/name` and `secrets.v1.core` are one resource.

    Denying only the bare word would leave three trivial bypasses, so the value is
    normalised to its first path- and dot-separated component before comparison.
    """
    for spelling in ("secret", "secrets", "secret/db", "secrets.v1.core", "SECRETS"):
        with pytest.raises(Rejected, match="never permitted here"):
            validate(f"kubectl get {spelling}", spec, ctx=ctx)


def test_logs_tail_is_capped_and_forced(spec: dict, ctx: dict) -> None:
    assert validate("kubectl logs api-0", spec, ctx=ctx).argv[-2:] == ["--tail", "500"]
    with pytest.raises(Rejected, match="at most 2000"):
        validate("kubectl logs api-0 --tail 999999", spec, ctx=ctx)


def test_short_flags_refused_for_kubectl(spec: dict, ctx: dict) -> None:
    """`-f` is --follow on logs and --filename on apply; long form removes the class."""
    with pytest.raises(Rejected, match="long flags only"):
        validate("kubectl logs -f api-0", spec, ctx=ctx)


def test_describe_commands_advertises_the_denials(spec: dict) -> None:
    entry = spec_summary(spec)["kubectl"]
    assert "exec" in entry["never_permitted"]
    assert "secret" in entry["never_readable"]
