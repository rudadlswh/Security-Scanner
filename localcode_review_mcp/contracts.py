"""공통 입력 계약: 정규 ID, 상대 경로, 유한 JSON. 의미/신원 검증은 아니다."""
import json
import re
import unicodedata


def fail(code):
    from .workspace import ProductError
    raise ProductError(code)


def canonical_id(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 128
            or value != value.strip() or unicodedata.normalize('NFC', value) != value
            or any(unicodedata.category(c)[0] in {'C', 'Z'} for c in value)):
        fail('NONCANONICAL_ID')
    return value


def unique_ids(values):
    if not isinstance(values, list) or len(values) > 10000:
        fail('ID_LIST_INVALID')
    seen = set()
    for value in values:
        key = canonical_id(value).casefold()
        if key in seen:
            fail('ID_COLLISION')
        seen.add(key)
    return seen


def relative_path(value):
    if not isinstance(value, str) or not value or len(value) > 4096:
        fail('PATH_INVALID')
    if any(unicodedata.category(c)[0] == 'C' for c in value):
        fail('PATH_UNSAFE_CHARACTER')
    # Accept either separator at existing Windows call sites; do not silently normalize IDs.
    parts = value.replace('\\', '/').split('/')
    if value.startswith(('/', '\\')) or any(p == '..' for p in parts):
        fail('PATH_ESCAPE')
    if re.match(r'^[A-Za-z]:', value):
        fail('PATH_ESCAPE')
    reserved = re.compile(r'^(con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\.|$)', re.I)
    if any(not p or p == '.' or p.endswith((' ', '.')) or reserved.match(p)
           or any(c in p for c in ':<>"|?*') for p in parts):
        fail('PATH_UNSAFE_COMPONENT')
    return value


def bounded_document(value, maximum=4_194_304):
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > 64 or count > 100000:
            fail('JSON_COMPLEXITY_LIMIT')
        if isinstance(item, dict):
            if len(item) > 10000 or any(not isinstance(k, str) for k in item):
                fail('JSON_OBJECT_LIMIT')
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            if len(item) > 10000:
                fail('JSON_ARRAY_LIMIT')
            pending.extend((v, depth + 1) for v in item)
    try:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (ValueError, TypeError, UnicodeError, RecursionError):
        fail('JSON_VALUE_INVALID')
    if len(raw) > maximum:
        fail('JSON_SIZE_LIMIT')


def exact_fields(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        fail('CONTRACT_FIELDS_INVALID')
