package ro.gandesc.resourceserver.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsCustomizer corsCustomizer;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        corsCustomizer.corsCustomizer(http);

        return http.oauth2ResourceServer(j -> j.jwt().jwkSetUri("http://localhost:8080/oauth2/jwks"))
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .build();
    }
}
