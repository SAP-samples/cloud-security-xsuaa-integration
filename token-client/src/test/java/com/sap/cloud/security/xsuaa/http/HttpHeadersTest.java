/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.http;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.util.Lists.newArrayList;

public class HttpHeadersTest {

	private final HttpHeader header = new HttpHeader("a", "a_value");
	private final HttpHeader anotherHeader = new HttpHeader("b", "b_value");
	private final HttpHeader sameKeyDifferentValue = new HttpHeader("a", "different_value");

	@Test
	public void equals_sameHeaders_isEqual() {
		HttpHeaders headers1 = new HttpHeaders(header, anotherHeader);
		HttpHeaders headers2 = new HttpHeaders(header, anotherHeader);

		assertThat(headers1).isEqualTo(headers2);
	}

	@Test
	public void equals_orderDoesNotMatter_isEqual() {
		HttpHeaders firstHeaders = new HttpHeaders(newArrayList(anotherHeader, header));
		HttpHeaders secondHeaders = new HttpHeaders(newArrayList(header, anotherHeader));

		assertThat(firstHeaders).isEqualTo(secondHeaders);
	}

	@Test
	public void equals_differentHeaders_isNotEqual() {
		HttpHeaders headers1 = new HttpHeaders(header);
		HttpHeaders headers2 = new HttpHeaders(anotherHeader);
		HttpHeaders headers3 = new HttpHeaders(sameKeyDifferentValue);

		assertThat(headers1).isNotEqualTo(headers2).isNotEqualTo(headers3);
		assertThat(headers2).isNotEqualTo(headers3);
	}

	@Test
	public void toStringTest() {
		HttpHeaders headers = new HttpHeaders(header, anotherHeader);
		assertThat(headers).hasToString("HttpHeaders: [ \"a: a_value\", \"b: b_value\" ]");
	}
}
