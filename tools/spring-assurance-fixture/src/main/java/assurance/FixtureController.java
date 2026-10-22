package assurance;
import org.springframework.web.bind.annotation.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
/** 시나리오 준비·boolean 관찰·정리 전용. 루프백 시험 환경에서만 사용한다. */
@RestController
public class FixtureController {
    public static final Map<String,Boolean> flags=new ConcurrentHashMap<>();
    private final RecordRepository records;
    public FixtureController(RecordRepository records){this.records=records;}
    @GetMapping("/health") public Map<String,Boolean> health(){return Map.of("ok",true);}
    @PostMapping("/fixture/records/{id}") public Map<String,Boolean> seed(@PathVariable String id,@RequestBody Map<String,String> row){
        records.save(new AuditRecord(id,row.getOrDefault("owner","owner"),row.getOrDefault("label","normal")));
        return Map.of("exists",true);
    }
    @GetMapping("/fixture/records/{id}") public Map<String,Boolean> state(@PathVariable String id){return Map.of("exists",records.existsById(id));}
    @DeleteMapping("/fixture/records/{id}") public Map<String,Boolean> cleanup(@PathVariable String id){records.deleteById(id);return Map.of("exists",false);}
    @PostMapping("/fixture/probes/{id}") public Map<String,Boolean> reset(@PathVariable String id){flags.put(id,false);return Map.of("value",false);}
    @GetMapping("/fixture/probes/{id}") public Map<String,Boolean> probe(@PathVariable String id){return Map.of("value",flags.getOrDefault(id,false));}
    @GetMapping("/fixture/private") public String internal(){flags.put("ssrf",true);return "fixture-private";}
}
