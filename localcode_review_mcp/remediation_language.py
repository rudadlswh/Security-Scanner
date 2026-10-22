"""권고의 출처·저장소 표현을 문장 안에서 대조한다. 제한된 패턴이며 의미 검증기는 아니다.

입력은 모델의 자유문, 출력은 검토 필요 여부다. 명시적 사용 금지와 사용 제안을 구별하며
서로 다른 필드의 단어를 결합하지 않는다. 애매한 이중 부정은 검토 대상으로 남긴다.
"""
import re


def clauses(text: str) -> list[str]:
    # 대조 접속사 뒤의 긍정 주장을 앞의 부정문이 숨기지 못하게 한다.
    return [s.strip() for s in re.split(r"[.!?;\n]+|,\s*|하지만|그러나|\b(?:but|however)\b", text, flags=re.I) if s.strip()]


_SOURCE = re.compile(
    r"응답(?:\s*(?:헤더|본문|객체|데이터))?|헤더|본문|\b(?:response(?:\s+(?:header|body|object|data))?|header|body)\b"
    r"|(?:엔드포인트|\b(?:endpoint|API|DELETE|PUT|PATCH|POST)\b|/[A-Za-z])"
    r"[^.!?;\n]{0,90}?(?:반환(?:하는)?(?:\s*(?:리소스\s*)?객체)?|돌려주|리턴|결과\s*객체|\b(?:returns?|returned|result|output)\b)",
    re.I)


def _explicit_source_rejection(clause: str, start: int, end: int) -> bool:
    """알려진 금지 구문만 제외한다. 부정 단어 하나로 문장 전체를 통과시키지 않는다."""
    if re.search(r"않(?:는|은|으면|아도)[^.!?;]{0,24}(?:아니|안\s*(?:되|된))|not\s+(?:necessary|wrong|incorrect)\s+to", clause, re.I):
        return False
    before, after = clause[:start], clause[end:]
    if re.search(r"\b(?:do\s+not|don't|never|must\s+not|should\s+not)\s+(?:use|trust|read|take|obtain|derive)\s+[^.!?;]{0,55}$", before, re.I):
        return True
    # 객체/필드 수식과 함께 열거된 '변경 후 조회'까지의 부정은 같은 출처에 적용된다.
    suffix = r"(?:\s*(?:의|에서|내의|필드|값|소유자|ID|owner_id|정보|데이터|객체|을|를|는|도|나|또는|요청자의|주장|변경\s*후\s*조회))*"
    return bool(re.match(suffix + r"\s*(?:(?:원천|출처)(?:으?로)?\s*(?:삼지|사용하지|이용하지|신뢰하지)\s*(?:않|말)"
                        r"|(?:사용|이용|신뢰|조회)하지\s*(?:않|말)|대신\b)", after, re.I)
                or re.match(r"\s+(?:must|should)\s+not\s+be\s+(?:used|trusted)", after, re.I))


def response_source_requires_review(text: str) -> bool:
    for clause in clauses(text):
        for match in _SOURCE.finditer(clause):
            if not _explicit_source_rejection(clause, match.start(), match.end()):
                return True
    return False


_STORAGE = r"(?:데이터베이스|캐시|(?<![A-Za-z0-9_])(?:database|DB|cache)(?![A-Za-z0-9_]))"
_KOREAN_STORAGE = _STORAGE + r"(?:된)?(?:\s*(?:상태|데이터|정보|조회|저장소|사용))?"
_EXCLUSION = re.compile(
    _KOREAN_STORAGE + r"\s*(?:을|를|에|가|는|의)?\s*"
    r"(?:의존하지\s*않|사용하지\s*(?:않|말)|아닌|없이|배제(?!하지\s*않)|제외(?!하지\s*않))"
    r"|\b(?:avoid|exclude|without)\s+(?:the\s+)?" + _STORAGE
    + r"|\b(?:do\s+not|don't|never|must\s+not|should\s+not)\s+(?:use|rely\s+on)\s+(?:the\s+)?" + _STORAGE,
    re.I)


def storage_exclusion_requires_review(text: str) -> bool:
    """저장소 자체를 배제하는 표현만 찾는다. 'DB 조회 후 비소유자는 거부'는 배제가 아니다."""
    return any(_EXCLUSION.search(clause) for clause in clauses(text))


def actor_alias_requires_review(text: str) -> bool:
    """별칭 언급과 별칭 신뢰를 구분한다. 명시적인 토큰 검증 한 구문만 예외로 인정한다."""
    alias = r"(?<![A-Za-z0-9_])(?:request[._ ]actor|actor)(?![A-Za-z0-9_])"
    verified_context = (
        r"(?:DELETE\s*)?요청의\s*actor\s*\([A-Za-z0-9_-]+\)\s*에\s*대해\s*"
        r"(?:서버가\s*발행한\s*)?토큰\s*(?:또는|/)\s*세션(?:을\s*검증하여|\s*검증\s*후)\s*"
        r"(?:실제|현재)\s*주체\s*ID\s*를\s*확보(?:한다|합니다)"
    )
    for clause in clauses(text):
        if re.search(alias, clause, re.I) and not re.fullmatch(verified_context, clause, re.I):
            return True
    return False


def proposed_statuses(text: str, actual_statuses: set[int]) -> set[int]:
    """일치하는 현재 관찰의 좁은 서술만 제외하고 나머지 숫자는 계속 권고 검토한다."""
    codes = set()
    for sentence in re.split(r"[.!?;\n]+", text):
        for match in re.finditer(r"(?<!\d)[1-5]\d{2}(?!\d)", sentence):
            code = int(match[0])
            observed = (code in actual_statuses
                        and re.search(r"현재|실제|관찰", sentence[:match.start()])
                        and re.search(r"(?:상태\s*코드|HTTP)\s*$", sentence[:match.start()])
                        and re.match(r"\s*(?:가|이)?\s*반환(?:되고|되었|됐|됩니다|된다)", sentence[match.end():])
                        and not re.search(r"해야|하도록|기대|수정|변경|권고|대신|원한다|원합니다", sentence))
            if not observed:
                codes.add(code)
    return codes
