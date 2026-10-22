/*
 * [한글 기능 설명]
 * 기능: 작은 합성 예제의 두 삭제 메서드를 직접 호출해 보안 정책과 실제 동작을 비교할 원자료를 낸다.
 * 시작점/입력: main에서 소유자/비작성자/미인증/대상 없음의8시나리오.
 * 이어지는 기능: probe → ReviewSample 메서드 → 변경 전후 상태 JSONL → check_review_sample_security.py의 정책 대조.
 * 주의: 대상 Java는 해시로 고정한 예제뿐이다. 실제 HTTP DAST나 일반 프로젝트 코드 자동 실행기가 아니다.
 */

/** Local behavior probe for the synthetic ReviewSample fixture only. */
public final class SecurityProbe {
    public static void main(String[] args) {
        for (String method : new String[]{"deleteWithOwnerCheck", "deleteWithoutOwnerCheck"}) {
            probe(method, "owner", new ReviewSample.Caller(10), 1);
            probe(method, "non_owner", new ReviewSample.Caller(20), 1);
            probe(method, "anonymous", null, 1);
            probe(method, "missing", new ReviewSample.Caller(10), 999);
        }
    }

    private static void probe(String method, String actor, ReviewSample.Caller caller, long id) {
        ReviewSample sample = new ReviewSample(new ReviewSample.Task(1, 10));
        boolean before = sample.exists(1);
        String outcome;
        try {
            if (method.equals("deleteWithOwnerCheck")) sample.deleteWithOwnerCheck(id, caller);
            else sample.deleteWithoutOwnerCheck(id, caller);
            outcome = "DELETED";
        } catch (SecurityException denied) {
            outcome = "DENIED";
        } catch (java.util.NoSuchElementException absent) {
            outcome = "NOT_FOUND";
        }
        System.out.printf("{\"method\":\"%s\",\"actor\":\"%s\",\"outcome\":\"%s\","
                + "\"task_existed_before\":%s,\"task_exists_after\":%s}%n",
                method, actor, outcome, before, sample.exists(1));
    }
}
