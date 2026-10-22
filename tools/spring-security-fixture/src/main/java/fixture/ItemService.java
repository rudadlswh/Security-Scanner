package fixture;

import java.sql.SQLException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/** 정상 경로는 삭제 전에 소유자를 비교한다. unsafe 경로는 의도한 결함 재현용이다. */
@Service
public class ItemService {
    private final ItemRepository items;
    public ItemService(ItemRepository items) { this.items = items; }

    public void deleteSafe(String id, String caller) throws SQLException {
        String owner = items.owner(id);
        if (owner == null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        if (!owner.equals(caller)) throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        items.delete(id);
    }

    public void deleteUnsafe(String id) throws SQLException {
        items.delete(id); // 의도적 결함: 인증된 비소유자도 삭제 가능하다.
    }
}
