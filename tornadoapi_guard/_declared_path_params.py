from collections.abc import Iterable, Iterator

from guard_core._misconfiguration import config_logger
from guard_core._utils.route_gate import declared_path_param_problems as engine_problems
from guard_core.decorators.base import BaseSecurityDecorator
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
) -> list[str]:
    router = getattr(application, "default_router", None)
    if guard_decorator is None or router is None:
        return []
    problems: list[str] = []
    for template, handler_class in _templates_and_handlers(router.rules):
        for route_id in sorted(_route_ids_of(handler_class)):
            route_config = guard_decorator.get_route_config(route_id)
            declared = getattr(route_config, "excluded_detection_path_params", None)
            if not declared:
                continue
            for name, problem in engine_problems(template, declared).items():
                problems.append(
                    f"@detection_exclusion(path_params=...) on route {route_id!r} "
                    f"declares {name!r}, which {problem}"
                )
    return problems


def warn_at_first_request(
    application: Application, guard_decorator: BaseSecurityDecorator | None
) -> None:
    for problem in declared_path_param_problems(application, guard_decorator):
        config_logger.warning(problem)
