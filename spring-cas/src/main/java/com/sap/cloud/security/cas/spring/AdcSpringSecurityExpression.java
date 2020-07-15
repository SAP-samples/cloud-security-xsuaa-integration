package com.sap.cloud.security.cas.spring;

import com.sap.cloud.security.cas.client.AdcService;
import com.sap.cloud.security.cas.client.AdcServiceRequest;
import com.sap.cloud.security.cas.client.AdcServiceRequestDefault;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Map;

/**
 */
public class AdcSpringSecurityExpression extends SecurityExpressionRoot implements MethodSecurityExpressionOperations {
	private static final String[] NO_ATTRIBUTES = new String[]{};

	public static final String ZONE_UUID_KEY = "zone_uuid";
	public static final String USER_UUID_KEY = "user_uuid";
	public static final String XSUAA_USER_ID = "user_id";
	public static final String ZID = "zid";

	private Logger logger = LoggerFactory.getLogger(getClass());
	private AdcService service;
	private String userId;
	private String zoneId;

	public AdcSpringSecurityExpression(JwtAuthenticationToken authentication) {
		super(authentication);
		logger.debug("Create AdcSpringSecurityExpression with jwtAuthenticationToken");


		extractAttributesFromAuthentication(authentication);
		setTrustResolver(new AuthenticationTrustResolverImpl());
	}

	public AdcSpringSecurityExpression(Authentication authentication) {
		super(authentication);
		logger.debug("Create AdcSpringSecurityExpression with authentication");

		extractAttributesFromPrincipal(authentication.getPrincipal());
		setTrustResolver(new AuthenticationTrustResolverImpl());
	}

	public AdcSpringSecurityExpression withAdcService(AdcService service) {
		this.service = service;
		return this;
	}

	//    public String getScopeExpression(String localScope) {
	//        // http://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/expression/OAuth2SecurityExpressionMethods.html
	//        return "#oauth2.hasScope('" + getGlobalScope(localScope) + "')";
	//    }

	public boolean forAction(String action) {
		return forResourceAction(null, action, NO_ATTRIBUTES);
	}

	public boolean forAction(String action, String... attributes) {
		return forResourceAction(null, action, attributes);
	}

	public boolean forResource(String resource) {
		return forResourceAction(resource, null, NO_ATTRIBUTES);
	}

	public boolean forResource(String resource, String... attributes) {
		return forResourceAction(resource, null, attributes);
	}

	public boolean forResourceAction(String resource, String action) {
		return forResourceAction(resource, action, NO_ATTRIBUTES);
	}

	public boolean forResourceAction(String resource, String action, String... attributes) {

		AdcServiceRequest request = new AdcServiceRequestDefault(zoneId, userId)
				.withAction(action)
				.withResource(resource)
				.withAttributes(attributes);

		boolean isAuthorized = checkAuthorization(request);

		logger.info("Is user {} (zoneId {}) authorized to perform action '{}' on resource '{}' and attributes '{}' ? {}",
				this.userId, this.zoneId, action, resource, attributes, isAuthorized);

		return isAuthorized;
	}

	private boolean checkAuthorization(AdcServiceRequest request) {
		try {
			return service.isUserAuthorized(request).getResult();
		} catch (Exception e) { // TODO improve
			logger.error("Error accessing ADC service.", e);
		}
		return false;
	}

	@Override public void setFilterObject(Object o) {
		Object filter = o;
	}

	@Override public Object getFilterObject() {
		return null;
	}

	@Override public void setReturnObject(Object o) {
	}

	@Override public Object getReturnObject() {
		return null;
	}

	@Override public Object getThis() {
		return null;
	}

	private void extractAttributesFromAuthentication(JwtAuthenticationToken authentication) {
		Map<String, Object> attributes = authentication.getTokenAttributes();
		zoneId = (String) attributes.getOrDefault(ZONE_UUID_KEY, attributes.get(ZID));
		userId = (String) attributes.getOrDefault(USER_UUID_KEY, attributes.get(XSUAA_USER_ID));
		logger.debug("Extracted attribute zoneId={} and userId={} from authentication", zoneId, userId);
	}

	private void extractAttributesFromPrincipal(Object principal) {
		if (principal instanceof OAuth2AuthenticatedPrincipal) {
			OAuth2AuthenticatedPrincipal userPrincipal = (OAuth2AuthenticatedPrincipal) principal;
			zoneId = (String) userPrincipal.getAttributes()
					.getOrDefault(ZONE_UUID_KEY, userPrincipal.getAttribute(ZID));
			userId = userPrincipal.getAttribute(USER_UUID_KEY);
			logger.debug("Extracted attribute zoneId={} and userId={} from principal", zoneId, userId);
		}
	}
}
