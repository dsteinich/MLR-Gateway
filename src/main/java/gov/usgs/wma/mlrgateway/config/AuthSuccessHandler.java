package gov.usgs.wma.mlrgateway.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import com.netflix.zuul.context.RequestContext;

public class AuthSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

	private static final String AUTHORIZATION_HEADER = "Authorization";

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request,
			HttpServletResponse response, Authentication authentication)
			throws ServletException, IOException {

		
		response.addHeader(AUTHORIZATION_HEADER, getToken(authentication));
		getRedirectStrategy().sendRedirect(request, response, "http://localhost:8089/swagger-ui.html&auth="+getToken(authentication));
	}

	private String getToken(Authentication authentication) {
		RefreshableKeycloakSecurityContext securityContext = getRefreshableKeycloakSecurityContext(authentication);
		return buildBearerToken(securityContext);
	}

	private RefreshableKeycloakSecurityContext getRefreshableKeycloakSecurityContext(Authentication authentication) {
		if (authentication instanceof KeycloakAuthenticationToken) {
			return (RefreshableKeycloakSecurityContext) ((KeycloakAuthenticationToken) authentication).getCredentials();
		}
		return null;
	}

	private String buildBearerToken(RefreshableKeycloakSecurityContext securityContext) {
		return "Bearer " + securityContext.getTokenString();
	}
}
