package ma.enset.supplierservice.security;

import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeycloackAdapterConfig {
  @Bean
  public KeycloakSpringBootConfigResolver springBootConfigResolver() {
    return new KeycloakSpringBootConfigResolver();
  }
}
