package com.sap.cloud.security.test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.VcapServicesParser;
import com.sap.cloud.security.test.api.ApplicationServerConfiguration;
import com.sap.cloud.security.test.api.SecurityTestContext;
import com.sap.cloud.security.test.api.ServiceMockConfiguration;
import com.sap.cloud.security.test.jetty.JettyTokenAuthenticator;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.http.MediaType;
import org.apache.commons.io.IOUtils;
import org.eclipse.jetty.annotations.AnnotationConfiguration;
import org.eclipse.jetty.plus.webapp.EnvConfiguration;
import org.eclipse.jetty.plus.webapp.PlusConfiguration;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.webapp.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.Servlet;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static com.sap.cloud.security.config.cf.CFConstants.XSUAA.UAA_DOMAIN;
import static com.sap.cloud.security.xsuaa.client.OidcConfigurationService.DISCOVERY_ENDPOINT_DEFAULT;

public class SecurityTest
		implements SecurityTestContext, ServiceMockConfiguration, ApplicationServerConfiguration {

	protected static final Logger LOGGER = LoggerFactory.getLogger(SecurityTest.class);

	// DEFAULTS
	public static final String DEFAULT_APP_ID = "xsapp!t0815";
	public static final String DEFAULT_CLIENT_ID = "sb-clientId!t0815";
	public static final String DEFAULT_DOMAIN = "localhost";
	public static final String DEFAULT_URL = "http://localhost";

	protected static final String LOCALHOST_PATTERN = "http://localhost:%d";

	protected final Map<String, ServletHolder> applicationServletsByPath = new HashMap<>();
	protected final List<FilterHolder> applicationServletFilters = new ArrayList<>();
	// app server
	protected Server applicationServer;
	protected ApplicationServerOptions applicationServerOptions;
	protected boolean useApplicationServer;

	// mock server
	protected WireMockServer wireMockServer;
	protected RSAKeys keys;
	protected Service service;

	protected String clientId = DEFAULT_CLIENT_ID;
	protected String jwksUrl;
	private String issuerUrl;

	public SecurityTest(Service service) {
		this.service = service;
		this.keys = RSAKeys.generate();
		this.wireMockServer = new WireMockServer(options().dynamicPort());
		this.applicationServerOptions = ApplicationServerOptions.forService(service);
	}

	@Override
	public SecurityTest useApplicationServer() {
		return useApplicationServer(ApplicationServerOptions.forService(service));
	}

	@Override
	public SecurityTest useApplicationServer(ApplicationServerOptions applicationServerOptions) {
		this.applicationServerOptions = applicationServerOptions;
		useApplicationServer = true;
		return this;
	}

	@Override
	public SecurityTest addApplicationServlet(Class<? extends Servlet> servletClass, String path) {
		applicationServletsByPath.put(path, new ServletHolder(servletClass));
		return this;
	}

	@Override
	public SecurityTest addApplicationServlet(ServletHolder servletHolder, String path) {
		applicationServletsByPath.put(path, servletHolder);
		return this;
	}

	@Override
	public SecurityTest addApplicationServletFilter(Class<? extends Filter> filterClass) {
		applicationServletFilters.add(new FilterHolder(filterClass));
		return this;
	}

	@Override
	public SecurityTest setPort(int port) {
		wireMockServer = new WireMockServer(options().port(port));
		return this;
	}

	@Override
	public SecurityTest setKeys(String publicKeyPath, String privateKeyPath) {
		try {
			this.keys = RSAKeys.fromKeyFiles(publicKeyPath, privateKeyPath);
		} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new UnsupportedOperationException(e);
		}
		return this;
	}

	@Override
	public JwtGenerator getPreconfiguredJwtGenerator() {
		JwtGenerator jwtGenerator = JwtGenerator.getInstance(service, clientId).withPrivateKey(keys.getPrivate());
		if (jwksUrl == null || issuerUrl == null) {
			LOGGER.warn("Method getPreconfiguredJwtGenerator was called too soon. Cannot set mock jwks/issuer url!");
		}
		switch (service) {
		case XSUAA:
			jwtGenerator
					.withHeaderParameter(TokenHeader.JWKS_URL, jwksUrl)
					.withAppId(DEFAULT_APP_ID)
					.withClaimValue(TokenClaims.XSUAA.GRANT_TYPE, OAuth2TokenServiceConstants.GRANT_TYPE_USER_TOKEN);
		}
		return jwtGenerator.withClaimValue(TokenClaims.ISSUER, issuerUrl);
	}

	@Override
	public JwtGenerator getJwtGeneratorFromFile(String tokenJsonResource) {
		return JwtGenerator.getInstanceFromFile(service, tokenJsonResource)
				.withHeaderParameter(TokenHeader.JWKS_URL, jwksUrl)
				.withClaimValue(TokenClaims.ISSUER, issuerUrl)
				.withPrivateKey(keys.getPrivate());
	}

	@Override
	public OAuth2ServiceConfigurationBuilder getOAuth2ServiceConfigurationBuilderFromFile(
			String configurationResourceName) {
		return VcapServicesParser.fromFile(configurationResourceName)
				.getConfigurationBuilder()
				.withProperty(UAA_DOMAIN, URI.create(issuerUrl).getHost())
				.withUrl(issuerUrl);
	}

	@Override
	public Token createToken() {
		return getPreconfiguredJwtGenerator().createToken();
	}

	@Override
	public WireMockServer getWireMockServer() {
		return wireMockServer;
	}

	@Override
	@Nullable
	public String getApplicationServerUri() {
		if (useApplicationServer) {
			return String.format(LOCALHOST_PATTERN, applicationServer.getURI().getPort());
		}
		return null;
	}

	void startApplicationServer() throws Exception {
		WebAppContext context = createWebAppContext();
		ServletHandler servletHandler = createServletHandler(context);

		applicationServletsByPath
				.forEach((path, servletHolder) -> servletHandler.addServletWithMapping(servletHolder, path));
		applicationServletFilters.forEach((filterHolder) -> servletHandler
				.addFilterWithMapping(filterHolder, "/*", EnumSet.of(DispatcherType.REQUEST)));

		servletHandler
				.addFilterWithMapping(new FilterHolder(new SecurityFilter()), "/*", EnumSet.of(DispatcherType.REQUEST));

		applicationServer = new Server(applicationServerOptions.getPort());
		applicationServer.setHandler(context);
		applicationServer.start();
	}

	ServletHandler createServletHandler(WebAppContext context) {
		ConstraintSecurityHandler security = new ConstraintSecurityHandler();
		JettyTokenAuthenticator authenticator = new JettyTokenAuthenticator(
				applicationServerOptions.getTokenAuthenticator());
		security.setAuthenticator(authenticator);

		ServletHandler servletHandler = new ServletHandler();
		security.setHandler(servletHandler);
		context.setServletHandler(servletHandler);
		context.setSecurityHandler(security);

		return servletHandler;
	}

	WebAppContext createWebAppContext() {
		WebAppContext context = new WebAppContext();
		context.setConfigurations(new Configuration[] {
				new AnnotationConfiguration(), new WebXmlConfiguration(),
				new WebInfConfiguration(), new PlusConfiguration(), new MetaInfConfiguration(),
				new FragmentConfiguration(), new EnvConfiguration() });
		context.setContextPath("/");
		context.setResourceBase("src/main/java/webapp");
		context.setParentLoaderPriority(true);
		return context;
	}

	String createDefaultTokenKeyResponse() throws IOException {
		String encodedPublicKeyModulus = Base64.getUrlEncoder()
				.encodeToString(((RSAPublicKey) keys.getPublic()).getModulus().toByteArray());
		String encodedPublicKey = Base64.getEncoder().encodeToString(keys.getPublic().getEncoded());
		return IOUtils.resourceToString("/token_keys_template.json", StandardCharsets.UTF_8)
				.replace("$kid", getKeyId())
				.replace("$public_key", encodedPublicKey)
				.replace("$modulus", encodedPublicKeyModulus);
	}

	private String getKeyId() {
		return this.service == Service.IAS ? JwtGenerator.DEFAULT_KEY_ID_IAS : JwtGenerator.DEFAULT_KEY_ID;
	}

	String createDefaultOidcConfigurationResponse() throws IOException {
		return IOUtils.resourceToString("/oidcConfigurationTemplate.json", StandardCharsets.UTF_8)
				.replace("$issuer", wireMockServer.baseUrl());
	}

	/**
	 * Starts the Jetty application web server and the WireMock OAuthServer if not
	 * running. Otherwise it resets WireMock and configures the stubs. Additionally
	 * it generates the JWK URL. Should be called before each test. Starts the
	 * server only, if it was not yet started.
	 *
	 * @throws IOException
	 *             if the stub cannot be initialized
	 */
	public void setup() throws Exception {
		if (useApplicationServer && (applicationServer == null || !applicationServer.isStarted())) {
			startApplicationServer();
		}
		if (!wireMockServer.isRunning()) {
			wireMockServer.start();
		} else {
			wireMockServer.resetAll();
		}
		// TODO return JSON Media type
		OAuth2ServiceEndpointsProvider endpointsProvider = new XsuaaDefaultEndpoints(
				String.format(LOCALHOST_PATTERN, wireMockServer.port()));
		wireMockServer.stubFor(get(urlEqualTo(endpointsProvider.getJwksUri().getPath()))
				.willReturn(aResponse().withBody(createDefaultTokenKeyResponse())
						.withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON.value())));
		wireMockServer.stubFor(get(urlEqualTo(DISCOVERY_ENDPOINT_DEFAULT))
				.willReturn(aResponse().withBody(createDefaultOidcConfigurationResponse())
						.withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON.value())));
		jwksUrl = endpointsProvider.getJwksUri().toString();
		issuerUrl = wireMockServer.baseUrl();
	}

	/**
	 * Shuts down Jetty application web server and WireMock stub. Should be called
	 * when all tests are executed to avoid unwanted side-effects.
	 */
	public void tearDown() {
		shutdownWireMock();
		try {
			if (useApplicationServer) {
				applicationServer.stop();
			}
		} catch (Exception e) {
			LOGGER.error("Failed to stop jetty server", e);
		}
	}

	/**
	 * The {@code shutdown} method of WireMock does not block the main thread. This
	 * can cause issues if one static {@link SecurityTestRule} is reused in many
	 * test classes. Therefore we wait until the WireMock server has really been
	 * shutdown (or the maximum amount of tries has been reached).
	 */
	private void shutdownWireMock() {
		wireMockServer.shutdown();
		int maxTries = 100;
		for (int tries = 0; tries < maxTries && wireMockServer.isRunning(); tries++) {
			try {
				Thread.sleep(50);
			} catch (InterruptedException e) {
				LOGGER.warn("Got interrupted while waiting for WireMock to shutdown. Giving up!");
				Thread.currentThread().interrupt(); // restore the interrupted status
				break; // stop blocking
			}
		}
	}
}
