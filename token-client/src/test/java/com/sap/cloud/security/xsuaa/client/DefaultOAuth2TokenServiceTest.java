/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.servlet.MDCHelper;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.http.HttpHeadersFactory;
import com.sap.cloud.security.xsuaa.util.HttpClientTestFactory;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.assertj.core.util.Maps;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;

import static com.sap.cloud.security.servlet.MDCHelper.CORRELATION_ID;
import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class DefaultOAuth2TokenServiceTest {

	private static final String ACCESS_TOKEN = "abc123";
	private static final String REFRESH_TOKEN = "def456";
	private static final String TOKEN_TYPE = "bearer";
	private static final String VALID_JSON_RESPONSE = String
			.format("{expires_in: 10000, access_token: %s, refresh_token: %s, token_type: %s}",
					ACCESS_TOKEN, REFRESH_TOKEN, TOKEN_TYPE);
	private static final URI TOKEN_ENDPOINT_URI = URI.create("https://subdomain.myauth.server.com/oauth/token");

	private CloseableHttpClient mockHttpClient;
	private DefaultOAuth2TokenService cut;

	@BeforeEach
	public void setup() {
		mockHttpClient = Mockito.mock(CloseableHttpClient.class);
		cut = new DefaultOAuth2TokenService(mockHttpClient);
	}

	@Test
	public void emptyResponse_throwsException() throws IOException {
		CloseableHttpResponse response = HttpClientTestFactory.createHttpResponse("{}");
		when(mockHttpClient.execute(any(HttpPost.class), any(ResponseHandler.class))).thenAnswer(invocation -> {
			ResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(response);
		});

		assertThatThrownBy(() -> requestAccessToken(emptyMap()))
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining("expires_in");
	}

	@Test
	public void execute_yieldsTokenResponseWithCorrectData() throws IOException {
		CloseableHttpResponse response = HttpClientTestFactory.createHttpResponse(VALID_JSON_RESPONSE);
		when(mockHttpClient.execute(any(HttpPost.class), any(ResponseHandler.class))).thenAnswer(invocation -> {
			ResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(response);
		});

		OAuth2TokenResponse re = requestAccessToken(emptyMap());

		assertThat(re.getAccessToken()).isEqualTo(ACCESS_TOKEN);
		assertThat(re.getRefreshToken()).isEqualTo(REFRESH_TOKEN);
		assertThat(re.getExpiredAt()).isAfter(Instant.now());
		assertThat(re.getTokenType()).isEqualTo(TOKEN_TYPE);
	}

	@Test
	public void correlationIdProvisioning() throws IOException {
		CloseableHttpResponse response = HttpClientTestFactory.createHttpResponse(VALID_JSON_RESPONSE);
		when(mockHttpClient.execute(any(HttpPost.class), any(ResponseHandler.class))).thenAnswer(invocation -> {
			ResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(response);
		});

		ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
		Logger logger = (Logger) LoggerFactory.getLogger(MDCHelper.class);
		listAppender.start();
		logger.addAppender(listAppender);

		requestAccessToken(emptyMap());
		assertThat(listAppender.list.get(0).getLevel()).isEqualTo(Level.INFO);
		assertThat(listAppender.list.get(0).getMessage()).contains("was not found in the MDC");

		MDC.put(CORRELATION_ID, "my-correlation-id");
		requestAccessToken(emptyMap());
		assertThat(listAppender.list.get(1).getLevel()).isEqualTo(Level.DEBUG);
		assertThat(listAppender.list.get(1).getArgumentArray()[1]).isEqualTo(("my-correlation-id"));
		MDC.clear();
	}

	@Test
	public void executeWithAdditionalParameters_putsParametersIntoPostBody() throws IOException {
		ArgumentCaptor<HttpPost> httpPostCaptor = ArgumentCaptor.forClass(HttpPost.class);
		CloseableHttpResponse response = HttpClientTestFactory.createHttpResponse(VALID_JSON_RESPONSE);
		when(mockHttpClient.execute(any(HttpPost.class), any(ResponseHandler.class))).thenAnswer(invocation -> {
			ResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(response);
		});

		requestAccessToken(Maps.newHashMap("myKey", "myValue"));

		verify(mockHttpClient, times(1)).execute(httpPostCaptor.capture(), any(ResponseHandler.class));
		HttpPost httpPost = httpPostCaptor.getValue();
		HttpEntity httpEntity = httpPost.getEntity();
		assertThat(httpEntity).isNotNull();
		String postBody = IOUtils.toString(httpEntity.getContent(), StandardCharsets.UTF_8);
		assertThat(postBody).contains("myKey=myValue");
	}

	@Test
	public void httpResponseWithErrorStatusCode_throwsExceptionContainingMessage() throws IOException {
		String unauthorizedResponseText = "Unauthorized!";
		CloseableHttpResponse response = HttpClientTestFactory
				.createHttpResponse(unauthorizedResponseText, HttpStatus.SC_UNAUTHORIZED);
		when(mockHttpClient.execute(any(HttpPost.class), any(ResponseHandler.class))).thenAnswer(invocation -> {
			ResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(response);
		});

		OAuth2ServiceException e = assertThrows(OAuth2ServiceException.class,
				() -> requestAccessToken(emptyMap()));

		assertThat(e.getHeaders().get(0)).isEqualTo("testHeader: testValue");
		assertThat(e.getHttpStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
		assertThat(e.getMessage())
				.contains(unauthorizedResponseText)
				.contains(TOKEN_ENDPOINT_URI.toString());
	}

	@Test
	public void retrieveToken_testCache() throws IOException {
		CloseableHttpResponse response = HttpClientTestFactory.createHttpResponse(VALID_JSON_RESPONSE);
		when(mockHttpClient.execute(any(HttpPost.class), any(ResponseHandler.class))).thenAnswer(invocation -> {
			ResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(response);
		});

		cut.retrieveAccessTokenViaClientCredentialsGrant(TOKEN_ENDPOINT_URI,
				new ClientCredentials("myClientId", "mySecret"), null, null, emptyMap(), false);
		cut.retrieveAccessTokenViaClientCredentialsGrant(TOKEN_ENDPOINT_URI,
				new ClientCredentials("myClientId", "mySecret"), null, null, emptyMap(), false);

		verify(mockHttpClient, times(1)).execute(any(HttpPost.class), any(ResponseHandler.class));
	}

	private OAuth2TokenResponse requestAccessToken(Map<String, String> optionalParameters)
			throws OAuth2ServiceException {
		HttpHeaders withoutAuthorizationHeader = HttpHeadersFactory.createWithoutAuthorizationHeader();
		return cut.requestAccessToken(TOKEN_ENDPOINT_URI, withoutAuthorizationHeader, optionalParameters);
	}

}
