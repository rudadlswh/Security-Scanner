package assurance;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import jakarta.persistence.EntityManager;
import java.util.*;
import java.security.Principal;
/** 故意로 만든 SQL/HTML/외부 요청 경로와 대응 정상 경로. 운영 배포 금지. */
@RestController
public class BoundaryController {
    private final EntityManager database;
    private final RestTemplate http=new RestTemplate();
    public BoundaryController(EntityManager database){this.database=database;}
    @GetMapping("/api/unsafe/search")
    public Map<String,Object> unsafeSearch(@RequestParam String label,Principal principal) {
        List<AuditRecord> rows=database.createQuery("select r from AuditRecord r where r.label = '"+label+"'",AuditRecord.class).getResultList();
        boolean leak=rows.stream().anyMatch(r->!r.ownerName.equals(principal.getName()));
        FixtureController.flags.put("sql",leak);
        return Map.of("cross_owner_visible",leak,"count",rows.size());
    }
    @GetMapping("/api/search")
    public Map<String,Object> search(@RequestParam String label,Principal principal) {
        List<AuditRecord> rows=database.createQuery("select r from AuditRecord r where r.label = :label",AuditRecord.class).setParameter("label",label).getResultList();
        boolean leak=rows.stream().anyMatch(r->!r.ownerName.equals(principal.getName()));
        FixtureController.flags.put("sql",leak);
        return Map.of("cross_owner_visible",leak,"count",rows.size());
    }
    @GetMapping(value="/api/unsafe/html",produces="text/html")
    public String unsafeHtml(@RequestParam String message){return message;}
    @GetMapping(value="/api/html",produces="text/html")
    public String html(@RequestParam String message){return HtmlUtils.htmlEscape(message);}
    @GetMapping("/api/unsafe/fetch")
    public String unsafeFetch(@RequestParam String url){return http.getForObject(url,String.class);}
    @GetMapping("/api/fetch")
    public String fetch(@RequestParam String target){
        if(!target.equals("public"))throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        return "fixed-public-response";
    }
}
