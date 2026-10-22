package assurance;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import java.util.Map;
/** Spring Security/JPA/H2 일회용 시험 서버. 외부 DB 설정을 사용하지 않는다. */
@SpringBootApplication
public class FixtureApplication {
    public static void main(String[] args) {
        SpringApplication app=new SpringApplication(FixtureApplication.class);
        app.setDefaultProperties(Map.of("spring.datasource.url","jdbc:h2:mem:lcr_assurance;DB_CLOSE_DELAY=-1",
            "spring.jpa.hibernate.ddl-auto","create-drop","spring.jpa.open-in-view","false",
            "spring.main.banner-mode","off"));
        app.run(args);
    }
}
