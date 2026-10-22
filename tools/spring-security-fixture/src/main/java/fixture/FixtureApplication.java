package fixture;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** 실제 Spring/Tomcat을 시작한다. DB 주소는 저장소의 H2 메모리 URL로 고정한다. */
@SpringBootApplication
public class FixtureApplication {
    public static void main(String[] args) {
        SpringApplication.run(FixtureApplication.class, args);
    }
}
