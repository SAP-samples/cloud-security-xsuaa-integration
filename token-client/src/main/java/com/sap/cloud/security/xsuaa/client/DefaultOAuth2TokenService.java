package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;

public class DefaultOAuth2TokenService extends AbstractOAuth2TokenService {

	private static final Logger LOGGER = LoggerFactory.getLogger(DefaultOAuth2TokenService.class);

	private final CloseableHttpClient httpClient;

	public DefaultOAuth2TokenService() {
		this(HttpClients.createDefault(), TokenCacheConfiguration.defaultConfiguration());
	}

	public DefaultOAuth2TokenService(@Nonnull CloseableHttpClient httpClient) {
		this(httpClient, TokenCacheConfiguration.defaultConfiguration());
	}

	public DefaultOAuth2TokenService(@Nonnull TokenCacheConfiguration tokenCacheConfiguration) {
		this(HttpClients.createDefault(), tokenCacheConfiguration);
	}

	public DefaultOAuth2TokenService(@Nonnull CloseableHttpClient httpClient,
			@Nonnull TokenCacheConfiguration tokenCacheConfiguration) {
		super(tokenCacheConfiguration);
		Assertions.assertNotNull(httpClient, "http client is required");
		this.httpClient = httpClient;
	}

	@Override
	protected OAuth2TokenResponse requestAccessToken(URI tokenEndpointUri, HttpHeaders headers,
			Map<String, String> parameters) throws OAuth2ServiceException {
		HttpPost httpPost = createHttpPost(tokenEndpointUri, headers, parameters);
		return executeRequest(httpPost);
	}

	private OAuth2TokenResponse executeRequest(HttpPost httpPost) throws OAuth2ServiceException {
		LOGGER.debug("Requesting access token from url {} with headers {}", httpPost.getURI(),
				httpPost.getAllHeaders());
		try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
			int statusCode = response.getStatusLine().getStatusCode();
			LOGGER.debug("Received statusCode {}", statusCode);
			if (statusCode == HttpStatus.SC_OK) {
				return handleResponse(response);
			} else {
				String responseBodyAsString = HttpClientUtil.extractResponseBodyAsString(response);
				LOGGER.debug("Received response body: {}", responseBodyAsString);
				throw OAuth2ServiceException.builder("Error retrieving JWT token")
						.withStatusCode(statusCode)
						.withUri(httpPost.getURI())
						.withResponseBody(responseBodyAsString)
						.build();
			}
		} catch (OAuth2ServiceException e) {
			throw e;
		} catch (IOException e) {
			throw new OAuth2ServiceException("Unexpected error retrieving JWT token: " + e.getMessage());
		}
	}

	private OAuth2TokenResponse handleResponse(HttpResponse response) throws IOException {
		String responseBody = HttpClientUtil.extractResponseBodyAsString(response);
		Map<String, Object> accessTokenMap = new JSONObject(responseBody).toMap();
		return convertToOAuth2TokenResponse(accessTokenMap);
	}

	private OAuth2TokenResponse convertToOAuth2TokenResponse(Map<String, Object> accessTokenMap)
			throws OAuth2ServiceException {
		String accessToken = getParameter(accessTokenMap, ACCESS_TOKEN);
		String refreshToken = getParameter(accessTokenMap, REFRESH_TOKEN);
		String expiresIn = getParameter(accessTokenMap, EXPIRES_IN);
		return new OAuth2TokenResponse(accessToken, convertExpiresInToLong(expiresIn),
				refreshToken);
	}

	private Long convertExpiresInToLong(String expiresIn) throws OAuth2ServiceException {
		try {
			return Long.parseLong(expiresIn);
		} catch (NumberFormatException e) {
			throw new OAuth2ServiceException(
					String.format("Cannot convert expires_in from response (%s) to long", expiresIn));
		}
	}

	private String getParameter(Map<String, Object> accessTokenMap, String key) {
		return String.valueOf(accessTokenMap.get(key));
	}

	private HttpPost createHttpPost(URI uri, HttpHeaders headers, Map<String, String> parameters)
			throws OAuth2ServiceException {
		HttpPost httpPost = new HttpPost(uri);
		headers.getHeaders().forEach((header) -> httpPost.setHeader(header.getName(), header.getValue()));
		try {
			List<BasicNameValuePair> basicNameValuePairs = parameters.entrySet().stream()
					.map(entry -> new BasicNameValuePair(entry.getKey(), entry.getValue()))
					.collect(Collectors.toList());
			httpPost.setEntity(new UrlEncodedFormEntity(basicNameValuePairs));
		} catch (UnsupportedEncodingException e) {
			throw new OAuth2ServiceException("Unexpected error parsing URI: " + e.getMessage());
		}
		return httpPost;
	}

}
