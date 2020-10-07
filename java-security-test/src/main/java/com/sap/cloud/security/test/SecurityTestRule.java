package com.sap.cloud.security.test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.test.api.ApplicationServerConfiguration;
import com.sap.cloud.security.test.api.SecurityTestContext;
import com.sap.cloud.security.test.api.ServiceMockConfiguration;
import com.sap.cloud.security.token.Token;
import org.eclipse.jetty.servlet.ServletHolder;
import org.junit.rules.ExternalResource;

import javax.annotation.Nullable;
import javax.servlet.Filter;
import javax.servlet.Servlet;

public class SecurityTestRule extends ExternalResource
		implements SecurityTestContext, ServiceMockConfiguration, ApplicationServerConfiguration {

	public static final String DEFAULT_APP_ID = SecurityTest.DEFAULT_APP_ID;
	public static final String DEFAULT_CLIENT_ID = SecurityTest.DEFAULT_CLIENT_ID;
	public static final String DEFAULT_DOMAIN = SecurityTest.DEFAULT_DOMAIN;

	SecurityTest base;

	private SecurityTestRule() {
		// see factory method getInstance()
	}

	/**
	 * Creates an instance of the test rule for the given service.
	 *
	 * @param service
	 *            the service for which the test rule should be created.
	 * @return the test rule instance.
	 */
	public static SecurityTestRule getInstance(Service service) {
		SecurityTestRule instance = new SecurityTestRule();
		instance.base = new SecurityTest(service);

		return instance;
	}

	@Override
	public SecurityTestRule useApplicationServer() {
		base.useApplicationServer();
		return this;
	}

	@Override
	public SecurityTestRule useApplicationServer(ApplicationServerOptions applicationServerOptions) {
		base.useApplicationServer(applicationServerOptions);
		return this;
	}

	@Override
	public SecurityTestRule addApplicationServlet(Class<? extends Servlet> servletClass, String path) {
		base.addApplicationServlet(servletClass, path);
		return this;
	}

	@Override
	public SecurityTestRule addApplicationServlet(ServletHolder servletHolder, String path) {
		base.addApplicationServlet(servletHolder, path);
		return this;
	}

	@Override
	public SecurityTestRule addApplicationServletFilter(Class<? extends Filter> filterClass) {
		base.addApplicationServletFilter(filterClass);
		return this;
	}

	@Override
	public SecurityTestRule setPort(int port) {
		base.setPort(port);
		return this;
	}

	@Override
	public SecurityTestRule setKeys(String publicKeyPath, String privateKeyPath) {
		base.setKeys(publicKeyPath, privateKeyPath);
		return this;
	}

	@Override
	protected void before() throws Exception {
		base.setup(); // starts WireMock (to stub communication to identity service)
	}

	@Override
	public JwtGenerator getPreconfiguredJwtGenerator() {
		return base.getPreconfiguredJwtGenerator();
	}

	@Override
	public JwtGenerator getJwtGeneratorFromFile(String tokenJsonResource) {
		return base.getJwtGeneratorFromFile(tokenJsonResource);
	}

	@Override
	public OAuth2ServiceConfigurationBuilder getOAuth2ServiceConfigurationBuilderFromFile(String configurationJson) {
		return base.getOAuth2ServiceConfigurationBuilderFromFile(configurationJson);
	}

	/**
	 * @deprecated use {@link #getOAuth2ServiceConfigurationBuilderFromFile(String)}
	 *             instead.
	 */
	@Deprecated
	public OAuth2ServiceConfigurationBuilder getConfigurationBuilderFromFile(String configurationJson) {
		return base.getOAuth2ServiceConfigurationBuilderFromFile(configurationJson);
	}

	/**
	 * @return the {@link SecurityTestContext} of this {@link SecurityTestRule}
	 */
	public SecurityTestContext getContext() {
		return base;
	}

	@Override
	public Token createToken() {
		return base.createToken();
	}

	/**
	 * @deprecated use {@link #getWireMockServer()} method instead. Note that
	 *             WireMockServer is the base class of WireMockRule.
	 *
	 */
	@Deprecated
	public WireMockRule getWireMockRule() {
		throw new UnsupportedOperationException(
				"Deprecated since version 2.6.0. Please use getWireMockServer instead. WireMockServer is the base class of WireMockRule.");
	}

	@Override
	public WireMockServer getWireMockServer() {
		return base.getWireMockServer();
	}

	@Nullable
	@Override
	public String getApplicationServerUri() {
		return base.getApplicationServerUri();
	}

	@Override
	protected void after() {
		base.tearDown();
	}

}
