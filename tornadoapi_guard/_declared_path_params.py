from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING

from guard_core.adapter_support import (
    Problem,
    config_logger,
    detection_exclusion_path_param_problems,
    report_declared_path_param_problems,
    route_unknown_to_decorator_problem,
)
from guard_core.decorators.base import BaseSecurityDecorator
from guard_core.models import SecurityConfig
from tornado.routing import Rule
from tornado.web import Application, RequestHandler

if TYPE_CHECKING:
    from tornadoapi_guard.middleware import SecurityMiddleware


def _nested_rules(target: object) -> Iterable[Rule] | None:
    if isinstance(target, Application):
        return target.default_router.rules
    return getattr(target, "rules", None)


def _guard_of_nested_application(
    target: object, walking: object
) -> "SecurityMiddleware | None":
    """The SecurityMiddleware of a nested Application that carries one of its own:
    its handlers run that middleware (SecurityHandler reads it from
    handler.application.settings, handler.py:17), so its decorator, not the outer
    one, decides whether their routes are known. The outer's own middleware serving
    a nested Application is not another one."""
    from tornadoapi_guard.middleware import SecurityMiddleware

    if not isinstance(target, Application):
        return None
    own = target.settings.get("security_middleware")
    return own if isinstance(own, SecurityMiddleware) and own is not walking else None


def _templates_and_handlers(
    rules: Iterable[Rule], walking: object, decorator: BaseSecurityDecorator | None
) -> Iterator[tuple[str, type[RequestHandler], BaseSecurityDecorator | None]]:
    """Each handler with the decorator of the guard that serves it."""
    for rule in rules:
        nested = _nested_rules(rule.target)
        pattern = getattr(getattr(rule.matcher, "regex", None), "pattern", None)
        if nested is not None:
            own = _guard_of_nested_application(rule.target, walking)
            if own is None:
                yield from _templates_and_handlers(nested, walking, decorator)
            else:
                yield from _templates_and_handlers(nested, own, own.guard_decorator)
        elif isinstance(pattern, str) and isinstance(rule.target, type):
            yield pattern, rule.target, decorator


def _route_ids_of(handler_class: type[RequestHandler]) -> set[str]:
    return {
        route_id
        for verb in handler_class.SUPPORTED_METHODS
        if isinstance(
            route_id := getattr(
                getattr(handler_class, verb.lower()), "_guard_route_id", None
            ),
            str,
        )
    }


def declared_path_param_problems(
    application: Application, guard_decorator: BaseSecurityDecorator | None
) -> list[Problem]:
    router = getattr(application, "default_router", None)
    if guard_decorator is None or router is None:
        return []
    problems: list[Problem] = []
    unknown: set[str] = set()
    walking = application.settings.get("security_middleware")
    for template, handler_class, decorator in _templates_and_handlers(
        router.rules, walking, guard_decorator
    ):
        for route_id in sorted(_route_ids_of(handler_class)):
            route_config = (
                None if decorator is None else decorator.get_route_config(route_id)
            )
            if route_config is None:
                if route_id not in unknown:
                    unknown.add(route_id)
                    problems.append(route_unknown_to_decorator_problem(route_id))
                continue
            declared = getattr(route_config, "excluded_detection_path_params", None)
            if not declared:
                continue
            problems += detection_exclusion_path_param_problems(
                route_id, template, declared
            )
    return problems


def report_declared_path_params(
    config: SecurityConfig,
    application: Application,
    guard_decorator: BaseSecurityDecorator | None,
    *,
    problems: list[Problem] | None = None,
    log_refusal: bool = False,
) -> None:
    """The one report point, at the first request and again whenever the rules
    change (add_handlers can add routes later). With fail_on_misconfiguration every
    request raises a fresh error from the cached problems and the new ones are
    logged once; without it each problem is warned once."""
    if problems is None:
        problems = declared_path_param_problems(application, guard_decorator)
    if log_refusal and problems and config.fail_on_misconfiguration:
        config_logger.error(
            "Every request is refused until this is fixed: %s", "; ".join(problems)
        )
    report_declared_path_param_problems(
        config, problems, logger=config_logger, stacklevel=2
    )
