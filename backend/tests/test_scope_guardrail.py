"""Which endpoints narrow their reads to the caller's teams, pinned as an inventory.

services/scope.py is the single place the rule is expressed, but applying it is opt-in: an endpoint
that forgets ``Depends(get_scope)`` returns every team's rows and no test fails, because the data it
leaks looks exactly like data the caller is allowed to have. That is how the asset_name branch of
scan upload stayed unscoped.

So the split is written down here. A new endpoint lands in neither list and fails this test, which
forces whoever adds it to say which side it is on rather than inherit the unsafe default.
"""

from fastapi.routing import APIRoute

from app.core.deps import get_scope
from app.main import app

# Endpoints that read asset-bound rows (findings, scans, components, analytics) and must be narrowed.
SCOPED = {
    ("DELETE", "/api/v1/assets/{asset_id}"),
    ("DELETE", "/api/v1/findings/{finding_id}/ticket/{link_id}"),
    ("DELETE", "/api/v1/gate-policies/{policy_id}"),
    ("DELETE", "/api/v1/triage-rules/{rule_id}"),
    ("GET", "/api/v1/acceptance-requests"),
    ("GET", "/api/v1/notifications"),
    ("GET", "/api/v1/vulnerabilities/{vuln_id}"),
    ("GET", "/api/v1/search"),
    ("GET", "/api/v1/products"),
    ("POST", "/api/v1/notifications/read"),
    ("POST", "/api/v1/acceptance-requests/{request_id}/approve"),
    ("POST", "/api/v1/acceptance-requests/{request_id}/reject"),
    ("POST", "/api/v1/findings/{finding_id}/acceptance-requests"),
    ("GET", "/api/v1/analytics/breakdown"),
    ("GET", "/api/v1/analytics/compliance"),
    ("GET", "/api/v1/analytics/coverage"),
    ("GET", "/api/v1/analytics/summary"),
    ("GET", "/api/v1/analytics/top"),
    ("GET", "/api/v1/analytics/trends"),
    ("GET", "/api/v1/assets"),
    ("GET", "/api/v1/assets/options"),
    ("GET", "/api/v1/assets/{asset_id}"),
    ("GET", "/api/v1/assets/{asset_id}/components"),
    ("GET", "/api/v1/assets/{asset_id}/sbom"),
    ("GET", "/api/v1/assets/{asset_id}/vex"),
    ("POST", "/api/v1/assets/{asset_id}/vex"),
    ("GET", "/api/v1/components"),
    ("GET", "/api/v1/components/licenses"),
    ("GET", "/api/v1/components/stats"),
    ("GET", "/api/v1/findings"),
    ("GET", "/api/v1/findings/export.csv"),
    ("GET", "/api/v1/findings/export.json"),
    ("GET", "/api/v1/findings/export.sarif"),
    ("GET", "/api/v1/findings/tags"),
    ("GET", "/api/v1/findings/{finding_id}"),
    ("GET", "/api/v1/findings/{finding_id}/events"),
    ("GET", "/api/v1/findings/{finding_id}/trackers"),
    ("GET", "/api/v1/gate-policies"),
    ("GET", "/api/v1/scans"),
    ("GET", "/api/v1/scans/{scan_id}"),
    ("GET", "/api/v1/scans/{scan_id}/diff"),
    ("GET", "/api/v1/triage-rules"),
    ("PATCH", "/api/v1/assets/{asset_id}"),
    ("PATCH", "/api/v1/findings/{finding_id}"),
    ("PATCH", "/api/v1/triage-rules/{rule_id}"),
    ("POST", "/api/v1/findings/bulk"),
    ("POST", "/api/v1/findings/bulk/matching"),
    ("POST", "/api/v1/findings/{finding_id}/comments"),
    ("POST", "/api/v1/findings/{finding_id}/ticket"),
    ("POST", "/api/v1/scans"),
    ("POST", "/api/v1/triage-rules"),
    ("POST", "/api/v1/triage-rules/preview"),
    ("POST", "/api/v1/triage-rules/{rule_id}/apply"),
    ("PUT", "/api/v1/gate-policies"),
}

# Endpoints that read no asset-bound rows, or only the caller's own (auth, preferences, tokens, views), or
# admin-only configuration that is global by nature. Listed so that a new endpoint cannot land unclassified.
UNSCOPED = {
    ("DELETE", "/api/v1/report-schedules/{schedule_id}"),
    ("GET", "/api/v1/report-schedules"),
    ("POST", "/api/v1/report-schedules"),
    ("POST", "/api/v1/report-schedules/{schedule_id}/send"),
    ("PUT", "/api/v1/report-schedules/{schedule_id}"),
    ("DELETE", "/api/v1/products/{product_id}"),
    ("PATCH", "/api/v1/products/{product_id}"),
    ("POST", "/api/v1/products"),
    ("DELETE", "/api/v1/integrations/{integration_id}"),
    ("DELETE", "/api/v1/teams/{team_id}"),
    ("DELETE", "/api/v1/tokens/{token_id}"),
    ("DELETE", "/api/v1/users/{user_id}"),
    ("DELETE", "/api/v1/views/{view_id}"),
    ("DELETE", "/api/v1/webhooks/{webhook_id}"),
    ("GET", "/api/v1/admin/audit"),
    ("GET", "/api/v1/admin/jobs"),
    ("GET", "/api/v1/admin/jobs/stats"),
    ("GET", "/api/v1/auth/me"),
    ("GET", "/api/v1/auth/mfa"),
    ("GET", "/api/v1/auth/oidc/callback"),
    ("GET", "/api/v1/auth/oidc/login"),
    ("GET", "/api/v1/auth/preferences"),
    ("GET", "/api/v1/components/license-policy"),
    ("GET", "/api/v1/integrations"),
    ("GET", "/api/v1/meta"),
    ("GET", "/api/v1/sla"),
    ("GET", "/api/v1/teams"),
    ("GET", "/api/v1/tokens"),
    ("GET", "/api/v1/users"),
    ("GET", "/api/v1/users/directory"),
    ("GET", "/api/v1/views"),
    ("GET", "/api/v1/webhooks"),
    ("GET", "/api/v1/webhooks/{webhook_id}/deliveries"),
    ("PATCH", "/api/v1/auth/preferences"),
    ("PATCH", "/api/v1/integrations/{integration_id}"),
    ("PATCH", "/api/v1/teams/{team_id}"),
    ("PATCH", "/api/v1/users/{user_id}"),
    ("PATCH", "/api/v1/views/{view_id}"),
    ("PATCH", "/api/v1/webhooks/{webhook_id}"),
    ("POST", "/api/v1/admin/jobs/{job_id}/retry"),
    ("POST", "/api/v1/assets"),
    ("POST", "/api/v1/auth/change-password"),
    ("POST", "/api/v1/auth/forgot-password"),
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/login/mfa"),
    ("POST", "/api/v1/auth/logout"),
    ("POST", "/api/v1/auth/logout-all"),
    ("POST", "/api/v1/auth/mfa/disable"),
    ("POST", "/api/v1/auth/mfa/enable"),
    ("POST", "/api/v1/auth/mfa/recovery-codes"),
    ("POST", "/api/v1/auth/mfa/setup"),
    ("POST", "/api/v1/auth/refresh"),
    ("POST", "/api/v1/auth/reset-password"),
    ("POST", "/api/v1/integrations"),
    ("POST", "/api/v1/integrations/{integration_id}/check"),
    ("POST", "/api/v1/teams"),
    ("POST", "/api/v1/tokens"),
    ("POST", "/api/v1/users"),
    ("POST", "/api/v1/views"),
    ("POST", "/api/v1/webhooks"),
    ("POST", "/api/v1/webhooks/{webhook_id}/rotate-secret"),
    ("POST", "/api/v1/webhooks/{webhook_id}/test"),
    ("PUT", "/api/v1/components/license-policy"),
    ("PUT", "/api/v1/sla"),
    ("PUT", "/api/v1/teams/{team_id}/members"),
}


def _uses_scope(route: APIRoute) -> bool:
    """Whether get_scope appears anywhere in this route's dependency tree."""
    stack, seen = [route.dependant], set()
    while stack:
        dep = stack.pop()
        if id(dep) in seen:
            continue
        seen.add(id(dep))
        if dep.call is get_scope:
            return True
        stack.extend(dep.dependencies)
    return False


def _routes() -> list[tuple[str, str, APIRoute]]:
    """Every API route, flattened, with its full path.

    Since FastAPI 0.141 ``app.routes`` holds a wrapper per included router rather than the routes
    themselves, and the wrapper keeps the include prefix separately from the router's own paths. The
    first version of this walk did not know that, found nothing, and every assertion below passed
    over an empty list -- which is what test_the_route_inventory_is_not_empty is here to stop.
    """
    out: list[tuple[str, str, APIRoute]] = []
    stack: list[tuple[str, object]] = [("", r) for r in app.routes]
    while stack:
        prefix, route = stack.pop()
        if isinstance(route, APIRoute):
            path = prefix + route.path
            if path.startswith("/api/"):
                for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
                    out.append((method, path, route))
        elif (inner := getattr(route, "original_router", None)) is not None:
            context = getattr(route, "include_context", None)
            stack.extend((prefix + (getattr(context, "prefix", "") or ""), r) for r in inner.routes)
        else:
            stack.extend((prefix, r) for r in getattr(route, "routes", []))
    return sorted(out, key=lambda r: (r[1], r[0]))


def test_the_route_inventory_is_not_empty():
    """Guards the guard: every assertion below is vacuous if this walk finds nothing."""
    found = _routes()
    assert len(found) > 80, f"expected the full API surface, walked only {len(found)} routes"
    assert any(p == "/api/v1/findings" for _, p, _ in found)


def test_the_endpoints_that_must_narrow_by_team_all_do():
    missing = {(m, p) for m, p, r in _routes() if (m, p) in SCOPED and not _uses_scope(r)}
    assert not missing, f"these endpoints no longer narrow by team: {sorted(missing)}"


def test_no_endpoint_is_scoped_without_being_listed():
    """Keeps the inventory honest: a scoped endpoint missing from SCOPED would make the test above
    pass for the wrong reason if it were ever removed from the list."""
    extra = {(m, p) for m, p, r in _routes() if _uses_scope(r) and (m, p) not in SCOPED}
    assert not extra, f"these endpoints narrow by team but are not listed in SCOPED: {sorted(extra)}"


def test_every_endpoint_has_been_classified():
    """A new endpoint is in neither list, so this fails until somebody decides which it is."""
    unclassified = {(m, p) for m, p, _ in _routes() if (m, p) not in SCOPED | UNSCOPED}
    assert not unclassified, (
        "classify these endpoints in tests/test_scope_guardrail.py: SCOPED if they read asset-bound rows "
        f"(and then narrow with Depends(get_scope)), UNSCOPED otherwise: {sorted(unclassified)}"
    )


def test_the_inventories_do_not_overlap_or_go_stale():
    """An endpoint in both lists, or one that no longer exists, means the inventory is out of date."""
    assert not SCOPED & UNSCOPED, f"listed as both scoped and unscoped: {sorted(SCOPED & UNSCOPED)}"
    stale = (SCOPED | UNSCOPED) - {(m, p) for m, p, _ in _routes()}
    assert not stale, f"these endpoints no longer exist: {sorted(stale)}"
