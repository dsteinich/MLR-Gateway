package gov.usgs.wma.mlrgateway.config;

import java.io.InputStream;

import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.spi.HttpFacade.Request;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

//@Component
public class arg implements KeycloakConfigResolver {

	@Value(value = "classpath:keycloak1.json")
	private Resource restKeycloak;
	@Value(value = "classpath:keycloak2.json")
	private Resource uiKeycloak;

	@Override
	public KeycloakDeployment resolve(Request facade) {
		try {
			if (facade.getHeader("Authorization") != null) {
				InputStream is = restKeycloak.getInputStream();
				return KeycloakDeploymentBuilder.build(is);
			} else {
				InputStream is = uiKeycloak.getInputStream();
				return KeycloakDeploymentBuilder.build(is);
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
