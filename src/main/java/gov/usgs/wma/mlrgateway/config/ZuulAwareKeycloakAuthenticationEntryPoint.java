package gov.usgs.wma.mlrgateway.config;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationEntryPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponents;

@Component
public class ZuulAwareKeycloakAuthenticationEntryPoint extends KeycloakAuthenticationEntryPoint {

	@Autowired
	public ZuulAwareKeycloakAuthenticationEntryPoint(AdapterDeploymentContext adapterDeploymentContext) {
		super(adapterDeploymentContext);
	}

	private final Logger logger = LoggerFactory.getLogger(ZuulAwareKeycloakAuthenticationEntryPoint.class);

	@Override
	protected void commenceLoginRedirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
		String prefix = request.getHeader("x-forwarded-prefix");
		UriComponents components =
				ServletUriComponentsBuilder.fromRequest(request)
				.replacePath((prefix != null ? prefix : "") + "/sso/login").build();

		logger.info("Redirecting to login URI: {}", components.toUriString());
		response.sendRedirect(components.toUriString());
	}

}
