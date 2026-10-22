package assurance;
import jakarta.persistence.*;
/** H2 메모리 테이블의 소유권·조회 시험 데이터. */
@Entity @Table(name="audit_records")
public class AuditRecord {
    @Id public String id;
    public String ownerName;
    public String label;
    public AuditRecord() {}
    public AuditRecord(String id,String ownerName,String label){this.id=id;this.ownerName=ownerName;this.label=label;}
}
