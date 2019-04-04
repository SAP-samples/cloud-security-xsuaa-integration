package com.sap.cloud.security.xsuaa.mock;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;

public class XsuaaRequestDispatcher extends Dispatcher {
	protected static final String RESPONSE_404 = "Xsuaa mock authorization server does not support this request";
	protected static final String RESPONSE_401 = "Xsuaa mock authorization server can't authenticate client/user";
	protected static final String RESPONSE_500 = "Xsuaa mock authorization server can't process request";
	protected static final String PATH_TOKEN_KEYS_TEMPLATE = "/mock/token_keys_template.json";
	protected static final String PATH_PUBLIC_KEY = "/mock/publicKey.txt";
	protected final Log logger = LogFactory.getLog(XsuaaRequestDispatcher.class);

	@Override
	public MockResponse dispatch(RecordedRequest request) {
		if ("/testdomain/token_keys".equals(request.getPath())) {
			String subdomain = "testdomain";
			return getTokenKeyForKeyId(PATH_TOKEN_KEYS_TEMPLATE, "legacy-token-key-" + subdomain);
		}
		if (request.getPath().endsWith("/token_keys")) {
			return getTokenKeyForKeyId(PATH_TOKEN_KEYS_TEMPLATE, "legacy-token-key");
		}
		return getResponse(RESPONSE_404, HttpStatus.NOT_FOUND);
	}

	protected MockResponse getResponseFromFile(String path, HttpStatus status) {
		try {
			String body = readFromFile(path);
			return getResponse(body, status);
		} catch (Exception e) {
			return getInternalErrorResponse(e.getMessage());
		}
	}

	protected MockResponse getResponse(String message, HttpStatus status) {
		return new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setResponseCode(status.value())
				.setBody(message);
	}

	protected MockResponse getTokenKeyForKeyId(String pathToTemplate, String keyId) {
		try {
			String publicKey = readFromFile(PATH_PUBLIC_KEY);
			String body = readFromFile(pathToTemplate)
					.replace("$kid", keyId)
					.replace("$public_key", publicKey);
			return getResponse(body, HttpStatus.OK);
		} catch (Exception e) {
			return getInternalErrorResponse(e.getMessage());
		}
	}

	protected String readFromFile(String path) throws IOException {
		return IOUtils.resourceToString(path, StandardCharsets.UTF_8);
	}

	protected MockResponse getInternalErrorResponse(String message) {
		logger.warn(message);
		return getResponse(RESPONSE_500 + ": " + message, HttpStatus.INTERNAL_SERVER_ERROR);
	}

}
