package assurance;
import org.springframework.context.annotation.*;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
/** 고정 시험 계정/HTTP Basic 전용. CSRF 비활성화나 noop 암호는 운영 권고가 아니다. */
@Configuration
public class SecurityConfiguration {
    @Bean SecurityFilterChain chain(HttpSecurity http) throws Exception {
        return http.csrf(c->c.disable()).authorizeHttpRequests(a->a.requestMatchers("/health","/fixture/**").permitAll()
            .anyRequest().authenticated()).httpBasic(Customizer.withDefaults()).build();
    }
    @Bean UserDetailsService users() {
        return new InMemoryUserDetailsManager(
            User.withUsername("owner").password("{noop}fixture-only").roles("USER").build(),
            User.withUsername("other").password("{noop}fixture-only").roles("USER").build());
    }
}
