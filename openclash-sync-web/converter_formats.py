"""Bounded, non-executing external config parsers. No network or filesystem reads.

PyYAML is loaded by the Web bootstrap from its pinned vendor. TOML uses the
Python 3.11+ standard library (production is Python 3.12); no global pip install.
"""
from __future__ import annotations
import json
import math
import re

import yaml

from subscription_converter import ConverterError

SURROGATE = re.compile(r'[\ud800-\udfff]')


def shape(value):
    stack, count = [(value, 0)], 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > 20000 or depth > 32:
            raise ConverterError('CONFIG_FORMAT')
        if isinstance(item, dict):
            if not all(isinstance(key, str) and not SURROGATE.search(key) for key in item):
                raise ConverterError('CONFIG_FORMAT')
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            if SURROGATE.search(item):
                raise ConverterError('CONFIG_FORMAT')
        elif not isinstance(item, (bool, int, float, type(None))) or isinstance(item, float) and not math.isfinite(item):
            raise ConverterError('CONFIG_FORMAT')
    return value


class BoundedSafeLoader(yaml.SafeLoader):
    """Apply budgets while parsing, not in a second whole-document scan.

    Count value nodes (mapping keys are checked by each strict constructor).
    Root depth is one; converter shape() uses zero-based depth.
    """
    max_tokens = 100001
    max_nodes = 20000
    max_depth = 33

    def __init__(self, stream):
        self._token_count = self._value_count = self._compose_depth = 0
        super().__init__(stream)

    def get_token(self):
        token = super().get_token()
        if token is not None:
            self._token_count += 1
            if self._token_count > self.max_tokens:
                raise yaml.constructor.ConstructorError(None, None, "YAML 词法项目过多", token.start_mark)
            if isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken)):
                raise yaml.constructor.ConstructorError(None, None, "YAML 不允许锚点或别名", token.start_mark)
        return token

    def compose_node(self, parent, index):
        if parent is None or index is not None:
            self._value_count += 1
        self._compose_depth += 1
        try:
            if self._value_count > self.max_nodes or self._compose_depth > self.max_depth:
                raise yaml.constructor.ConstructorError(None, None, "YAML 结构过深或项目过多", self.peek_event().start_mark)
            return super().compose_node(parent, index)
        finally:
            self._compose_depth -= 1


class UniqueLoader(BoundedSafeLoader):
    def construct_scalar(self, node):
        value = super().construct_scalar(node)
        if SURROGATE.search(value):
            # JSON permits escaped UTF-16 pairs for a single Unicode scalar.
            # Normalize before duplicate-key checks; reject unpaired surrogates.
            try:
                return value.encode('utf-16-le', 'surrogatepass').decode('utf-16-le')
            except UnicodeError:
                raise ConverterError('CONFIG_FORMAT') from None
        return value

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, val_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result or key == '<<':
                raise ConverterError('CONFIG_FORMAT')
            result[key] = self.construct_object(val_node, deep=deep)
        return result


# PyYAML's YAML 1.1 resolver treats JSON spellings such as 1e+20 as strings.
# Keep the extra resolver local to this loader and preserve scalar roundtrips.
UniqueLoader.add_implicit_resolver(
    'tag:yaml.org,2002:float',
    re.compile(r'^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?[eE][-+]?[0-9]+$'),
    list('-0123456789'))


def yaml_load(value):
    try:
        return shape(yaml.load(value, Loader=UniqueLoader))
    except (yaml.YAMLError, ValueError, RecursionError, TypeError, AttributeError):
        raise ConverterError('CONFIG_FORMAT') from None


def json_load(value):
    """Strict JSON export intake; never silently discard duplicate fields."""
    def unique_object(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ConverterError('CONFIG_FORMAT')
            result[key] = item
        return result
    try:
        return shape(json.loads(value, object_pairs_hook=unique_object))
    except (ValueError, TypeError, RecursionError):
        raise ConverterError('CONFIG_FORMAT') from None


def is_toml(value):
    if not isinstance(value, str):
        raise ConverterError('CONFIG_FORMAT')
    # Our serializer quotes every key, including version. Accept both valid
    # quoted TOML spellings when loading a generated config again.
    # Every LF has its own anchor; do not rescan all following blank lines.
    return bool(re.search(r"""^[^\S\n]*(?:version|"version"|'version')\s*=""", value, re.M))


def load(value, *, kind=None):
    automatic = kind is None
    if automatic:
        kind = 'toml' if is_toml(value) else 'yaml'
    if kind == 'toml':
        try:
            import tomllib
        except ImportError:
            raise ConverterError('TOML_UNAVAILABLE') from None
        try:
            result = shape(tomllib.loads(value))
        except tomllib.TOMLDecodeError:
            # A version-looking line can be part of a YAML multiline scalar.
            # Retry only a failed heuristic, not explicit TOML or shape errors.
            if automatic:
                return load(value, kind='yaml')
            raise ConverterError('CONFIG_FORMAT') from None
        except (ValueError, TypeError, AttributeError, RecursionError):
            raise ConverterError('CONFIG_FORMAT') from None
    else:
        result = yaml_load(value)
    if not isinstance(result, dict):
        raise ConverterError('CONFIG_FORMAT')
    return result, kind


def dump(value, kind, *, compact=False):
    shape(value)
    def literal(value):
        # JSON permits code points that YAML folds/rejects; TOML also rejects
        # DEL. Escape those boundaries while keeping other Unicode readable.
        text = json.dumps(value, ensure_ascii=False, allow_nan=False,
                          separators=(',', ':') if compact else None)
        return re.sub(r'[\x7f-\x9f\u2028\u2029\ufffe\uffff]', lambda match: '\\u%04x' % ord(match[0]), text)
    if kind != 'toml':
        # JSON is a YAML 1.2 subset, avoids implicit tags/anchors, and preserves
        # the native structured YAML configuration keys exactly.
        return literal(value) + '\n'
    if not isinstance(value, dict):
        raise ConverterError('CONFIG_FORMAT')
    def item(value):
        if isinstance(value, dict):
            return '{' + ', '.join(literal(key) + ' = ' + item(val) for key, val in value.items()) + '}'
        if isinstance(value, list):
            return '[' + ', '.join(item(val) for val in value) + ']'
        if value is None:
            raise ConverterError('CONFIG_FORMAT')
        return literal(value)
    return '\n'.join(literal(key) + ' = ' + item(val) for key, val in value.items()) + '\n'
