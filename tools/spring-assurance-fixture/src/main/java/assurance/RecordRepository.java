package assurance;
import org.springframework.data.jpa.repository.JpaRepository;
/** 실제 Spring Data JPA 구현을 사용하며 저장소 대역이 아니다. */
public interface RecordRepository extends JpaRepository<AuditRecord,String> {}
