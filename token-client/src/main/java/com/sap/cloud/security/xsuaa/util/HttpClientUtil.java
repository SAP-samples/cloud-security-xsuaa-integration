/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.util;

import com.sap.cloud.security.xsuaa.Assertions;
import org.apache.http.HttpResponse;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

public class HttpClientUtil {

	private HttpClientUtil() {
		// use static methods
	}

	public static String extractResponseBodyAsString(HttpResponse response) throws IOException {
		Assertions.assertNotNull(response, "response must not be null.");
		return new BufferedReader(new InputStreamReader(response.getEntity().getContent()))
				.lines().collect(Collectors.joining(System.lineSeparator()));
	}

}
