package assurance;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import java.security.Principal;
/** 실제 인증 주체와 JPA 원장의 소유자를 비교하는 경로/검사가 빠진 경로를 대조한다. */
@RestController
public class RecordController {
    private final RecordRepository records;
    public RecordController(RecordRepository records){this.records=records;}
    @DeleteMapping("/api/records/{id}") @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(@PathVariable String id,Principal principal) {
        AuditRecord r=records.findById(id).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND));
        if(!r.ownerName.equals(principal.getName()))throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        records.delete(r);
    }
    @DeleteMapping("/api/unsafe/records/{id}") @ResponseStatus(HttpStatus.NO_CONTENT)
    public void removeUnsafe(@PathVariable String id,Principal principal) {
        records.deleteById(id);
    }
}
