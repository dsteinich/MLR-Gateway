package gov.usgs.wma.mlrgateway.config;

import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakPreAuthActionsFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@Configuration
@EnableWebSecurity
@ComponentScan(basePackageClasses = KeycloakSecurityComponents.class)
public class WebSecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

	@Value("${mlrServicePassword}")
	private String pwd;

	@Autowired
	ZuulAwareKeycloakAuthenticationEntryPoint zuulAwareKeycloakAuthenticationEntryPoint;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		super.configure(http);
		http
			.authorizeRequests()
//				.antMatchers("/workflows/**").permitAll()
				.antMatchers("/swagger-ui.html", "/swagger-resources/**", "/webjars/**", "/v2/**").permitAll()
				.antMatchers("/health/**", "/hystrix/**", "/hystrix.stream**", "/proxy.stream**", "/favicon.ico").permitAll()
				.anyRequest().fullyAuthenticated()
			.and()
				.formLogin().defaultSuccessUrl("/swagger-ui.html", true)
			.and()
				.logout().logoutSuccessUrl("/swagger-ui.html")
			.and()
				.formLogin().permitAll()
			.and()
				.logout().permitAll()
			.and()
				.csrf().disable()
				.cors()
//			.and()
//				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		;
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(keycloakAuthenticationProvider());
	}

	@Override
	protected AuthenticationEntryPoint authenticationEntryPoint() {
		return zuulAwareKeycloakAuthenticationEntryPoint;
	}

//	@Bean
//	public FilterRegistrationBean keycloakAuthenticationProcessingFilterRegistrationBean(
//			KeycloakAuthenticationProcessingFilter filter) {
//		FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
//		registrationBean.setEnabled(false);
//		return registrationBean;
//	}
//
//	@Bean
//	public FilterRegistrationBean keycloakPreAuthActionsFilterRegistrationBean(KeycloakPreAuthActionsFilter filter) {
//		FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
//		registrationBean.setEnabled(false);
//		return registrationBean;
//	}

	@Bean
	@Override
	protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
		return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
	}

	@Bean
	public KeycloakConfigResolver KeycloakConfigResolver() {
		return new arg();
//		return new KeycloakSpringBootConfigResolver();
	}

}

//@Configuration
//@EnableWebSecurity
//public class WebSecurityConfig extends KeycloakWebSecurityConfigurerAdapter {
//
//	@Autowired
//	ZuulAwareKeycloakAuthenticationEntryPoint zuulAwareKeycloakAuthenticationEntryPoint;
//
//	@Autowired
//	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
//		auth.authenticationProvider(keycloakAuthenticationProvider());
//	}
//
//	@Bean
//	@Override
//	protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
//		return new NullAuthenticatedSessionStrategy();
//	}
//
//	@Bean
//	public FilterRegistrationBean keycloakAuthenticationProcessingFilterRegistrationBean(
//			KeycloakAuthenticationProcessingFilter filter) {
////		filter.setAuthenticationSuccessHandler(new AuthSuccessHandler());
//		FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
//		registrationBean.setEnabled(false);
//		return registrationBean;
//	}
//
//	@Bean
//	public FilterRegistrationBean keycloakPreAuthActionsFilterRegistrationBean(
//			KeycloakPreAuthActionsFilter filter) {
//		FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
//		registrationBean.setEnabled(false);
//		return registrationBean;
//	}
//
//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
//		http
//			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//			.sessionAuthenticationStrategy(sessionAuthenticationStrategy())
//			.and()
//				.addFilterBefore(keycloakPreAuthActionsFilter(), LogoutFilter.class)
//				.addFilterBefore(keycloakAuthenticationProcessingFilter(), X509AuthenticationFilter.class)
//				.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint())
//			.and()
//				.csrf().disable()
//				.cors()
//			.and()
//				.authorizeRequests().anyRequest().fullyAuthenticated()
//		;
//	}
//
//	@Override
//	protected AuthenticationEntryPoint authenticationEntryPoint() {
//		return zuulAwareKeycloakAuthenticationEntryPoint;
//	}
//
////	@Bean
////	public KeycloakConfigResolver getKeycloakConfigResolver() {
////		
////	}
//}
