package ma.enset.supplierservice.security;


import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@KeycloakConfiguration
public class KeycloakSecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

  @Override
  protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
    return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
  }

  // gestion des user
  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    // dire à spring boot que je ne gère pas les users et les roles, je le délègue
    auth.authenticationProvider(keycloakAuthenticationProvider());
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    super.configure(http);
    // pour accéser à /product il faut s'authentifier d'abord
    http.authorizeRequests().antMatchers("/suppliers/**").hasAuthority("MANAGER");
  }
  
}

