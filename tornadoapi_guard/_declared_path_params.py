from collections.abc import Iterable, Iterator

from guard_core._misconfiguration import config_logger, report_misconfigurations
from guard_core._misconfiguration_kinds import Problem
from guard_core._utils.route_gate import detection_exclusion_path_param_problems
from guard_core.decorators.base import BaseSecurityDecorator
from guard_core.models import SecurityConfig
from tornado.routing import Rule
from tornado.web import Application, RequestHandler


def _nested_rules(target: object) -> Iterable[Rule] | None:
    if isinstance(target, Application):
        return target.default_router.rules
    return getattr(target, "rules", None)


def _templates_and_handlers(
    rules: Iterable[Rule],
) -> Iterator[tuple[str, type[RequestHandler]]]:
    for rule in rules:
        nested = _nested_rules(rule.target)
        pattern = getattr(getattr(rule.matcher, "regex", None), "pattern", None)
        if nested is not None:
            yield from _templates_and_handlers(nested)
        elif isinstance(pattern, str) and isinstance(rule.target, type):
            yield pattern, rule.target


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
    for template, handler_class in _templates_and_handlers(router.rules):
        for route_id in sorted(_route_ids_of(handler_class)):
            route_config = guard_decorator.get_route_config(route_id)
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
    reported: set[str] | None = None,
) -> None:
    """The one report point, at the first request and again whenever the rules
    change (add_handlers can add routes later). With fail_on_misconfiguration every
    request raises a fresh error from the cached problems and the new ones are
    logged once; without it each problem is warned once."""
    if problems is None:
        problems = declared_path_param_problems(application, guard_decorator)
    seen = set() if reported is None else reported
    fresh = [problem for problem in problems if str(problem) not in seen]
    seen.update(str(problem) for problem in fresh)
    if config.fail_on_misconfiguration:
        if fresh:
            config_logger.error(
                "Every request is refused until this is fixed: %s",
                "; ".join(fresh),
            )
        report_misconfigurations(config, problems, logger=config_logger, stacklevel=2)
        return
    report_misconfigurations(config, fresh, logger=config_logger, stacklevel=2)
