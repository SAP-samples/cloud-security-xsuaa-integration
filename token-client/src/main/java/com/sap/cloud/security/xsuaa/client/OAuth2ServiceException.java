/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Exception thrown to signal issues during communication with OAuth2 server.
 */
public class OAuth2ServiceException extends IOException {

	private static final long serialVersionUID = 1L;
	private Integer httpStatusCode = 0;
	private final List<String> headers = new ArrayList<>();

	public OAuth2ServiceException(String message) {
		super(message);
	}

	/**
	 * Creates an exception.
	 *
	 * @param message
	 *            the error message
	 * @param httpStatusCode
	 *            the status code of the HTTP service request
	 */
	public OAuth2ServiceException(String message, Integer httpStatusCode) {
		super(message);
		this.httpStatusCode = httpStatusCode != null ? httpStatusCode : 0;
	}

	/**
	 * Creates an exception.
	 *
	 * @param message
	 *            the error message
	 * @param httpStatusCode
	 *            the status code of the HTTP service request
	 * @param headers
	 * 	          the headers of the HTTP service request
	 */

	OAuth2ServiceException(String message, Integer httpStatusCode, List<String> headers) {
		this(message, httpStatusCode);
		this.headers.addAll(headers);
	}

	/**
	 * Returns the HTTP status code of the failed OAuth2 service request or
	 * {@code 0} e.g. in case the service wasn't called at all.
	 *
	 * @return status code or 0
	 */
	public Integer getHttpStatusCode() {
		return httpStatusCode;
	}

	/**
	 * Returns the HTTP headers of the failed OAuth2 service request
	 * @return list of HTTP headers
	 */
	public List<String> getHeaders() {
		return this.headers;
	}

	/**
	 * Creates an exception.
	 *
	 * @param message
	 *            the error message
	 */
	public static Builder builder(String message) {
		return new Builder(message);
	}

	public static class Builder {
		private final String message;
		private Integer httpStatusCode;
		private URI serverUri;
		private String responseBody;
		private final List<String> headers = new ArrayList<>();
		private String headersString;

		public Builder(String message) {
			this.message = message;
		}

		/**
		 * Parameterizes the Exception with an HTTP status code.
		 *
		 * @param httpStatusCode
		 *            the http status code
		 * @return the builder
		 */
		public Builder withStatusCode(int httpStatusCode) {
			this.httpStatusCode = httpStatusCode;
			return this;
		}

		public Builder withUri(URI serverUri) {
			this.serverUri = serverUri;
			return this;
		}

		public Builder withResponseBody(String responseBody) {
			this.responseBody = responseBody;
			return this;
		}

		public Builder withHeaders(String... headers) {
			List<String> headerList = Arrays.stream(headers).filter(Objects::nonNull).collect(Collectors.toList());

			this.headers.addAll(headerList);
			this.headersString = headerList.stream().collect(Collectors.joining(", ", "[", "]"));

			return this;
		}

		public OAuth2ServiceException build() {
			String m = Stream
					.of(this.message, createUriMessage(), createStatusCodeMessage(), createResponseBodyMessage(),
							createHeaderMessage())
					.filter(Objects::nonNull)
					.collect(Collectors.joining(". "));
			return new OAuth2ServiceException(m, httpStatusCode, headers);
		}

		private String createResponseBodyMessage() {
			return responseBody == null ? null : "Response body '" + responseBody + "'";
		}

		private String createStatusCodeMessage() {
			return httpStatusCode == null ? null : "Http status code " + httpStatusCode;
		}

		private String createUriMessage() {
			return serverUri == null ? null : "Server URI " + serverUri;
		}

		private String createHeaderMessage() {
			return headersString == null ? null : "Response Headers " + headersString;
		}

	}
}