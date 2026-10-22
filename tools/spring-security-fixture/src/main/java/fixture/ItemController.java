package fixture;

import java.sql.SQLException;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

/** 고정 테스트 신원만 받는 샘플이다. 실제 토큰 검증/Spring Security 구현이 아니다. */
@RestController
public class ItemController {
    private final ItemService service;
    private final ItemRepository items;
    public ItemController(ItemService service, ItemRepository items) { this.service = service; this.items = items; }

    private String actor(String header) {
        if ("Bearer fixture-owner".equals(header)) return "owner";
        if ("Bearer fixture-non-owner".equals(header)) return "non-owner";
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
    }
    private void observer(String header) {
        if (!"Bearer fixture-observer".equals(header)) throw new ResponseStatusException(HttpStatus.FORBIDDEN);
    }

    @GetMapping("/health")
    public Map<String, Object> health() throws SQLException {
        items.owner("health-probe"); // DB 연결/쿼리가 성공해야 준비 상태다.
        return Map.of("status", "UP", "database", "H2-memory");
    }

    @PostMapping("/test/fixtures/item") @ResponseStatus(HttpStatus.CREATED)
    public void setup(@RequestHeader(value="Authorization", required=false) String auth,
                      @RequestBody Map<String, String> input) throws SQLException {
        observer(auth);
        if (!"lcr-disposable-001".equals(input.get("id")) || !"owner".equals(input.get("owner")))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        items.put(input.get("id"), input.get("owner"));
    }

    @GetMapping("/test/fixtures/item/state")
    public Map<String, Boolean> state(@RequestHeader(value="Authorization", required=false) String auth) throws SQLException {
        observer(auth);
        return Map.of("exists", items.owner("lcr-disposable-001") != null);
    }

    @DeleteMapping("/test/fixtures/item") @ResponseStatus(HttpStatus.NO_CONTENT)
    public void cleanup(@RequestHeader(value="Authorization", required=false) String auth) throws SQLException {
        observer(auth);
        items.delete("lcr-disposable-001");
    }

    @DeleteMapping("/api/items/{id}") @ResponseStatus(HttpStatus.NO_CONTENT)
    public void safe(@PathVariable("id") String id,
                     @RequestHeader(value="Authorization", required=false) String auth) throws SQLException {
        service.deleteSafe(id, actor(auth));
    }

    @DeleteMapping("/api/unsafe/items/{id}") @ResponseStatus(HttpStatus.NO_CONTENT)
    public void unsafe(@PathVariable("id") String id,
                       @RequestHeader(value="Authorization", required=false) String auth) throws SQLException {
        actor(auth);
        service.deleteUnsafe(id);
    }
}
