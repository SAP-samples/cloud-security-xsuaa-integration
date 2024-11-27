/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.test.api.ApplicationServerConfiguration;
import com.sap.cloud.security.test.api.SecurityTestContext;
import com.sap.cloud.security.test.api.ServiceMockConfiguration;
import com.sap.cloud.security.token.Token;
import jakarta.servlet.Filter;
import jakarta.servlet.Servlet;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.junit.rules.ExternalResource;

import javax.annotation.Nullable;

@Deprecated(since = "3.6.0", forRemoval = true)
/**
 * @deprecated since 3.6.0. Use {@link XsuaaExtension.class} or {@link IasExtension.class} in a JUnit5 test instead.
 */
public class SecurityTestRule extends ExternalResource
		implements SecurityTestContext, ServiceMockConfiguration, ApplicationServerConfiguration {

	public static final String DEFAULT_APP_ID = SecurityTest.DEFAULT_APP_ID;
	public static final String DEFAULT_CLIENT_ID = SecurityTest.DEFAULT_CLIENT_ID;
	public static final String DEFAULT_DOMAIN = SecurityTest.DEFAULT_DOMAIN;
	public static final String DEFAULT_UAA_DOMAIN = SecurityTest.DEFAULT_UAA_DOMAIN;

	SecurityTest base;

	private SecurityTestRule() {
		// see factory method getInstance()
	}

	/**
	 * Creates an instance of the test rule for the given service.
	 *
	 * @param service
	 * 		the service for which the test rule should be created.
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
	 * @return the {@link SecurityTestContext} of this {@link SecurityTestRule}
	 */
	public SecurityTestContext getContext() {
		return base;
	}

	@Override
	public Token createToken() {
		return base.createToken();
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