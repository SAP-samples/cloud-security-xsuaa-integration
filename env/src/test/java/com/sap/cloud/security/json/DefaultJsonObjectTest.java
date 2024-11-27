/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.json;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class DefaultJsonObjectTest {

	private static final Instant FIRST_OF_APRIL = LocalDate.of(2019, 4, 1).atStartOfDay().toInstant(ZoneOffset.UTC);

	private static final String KEY_1 = "key-1";
	private static final String KEY_2 = "key-2";

	private static final String STRING_TEXT = "string text";
	private static final String STRING_VALUE = "\"" + STRING_TEXT + "\"";

	private static final String STRING_LIST_VALUE = "[\"a\", \"b\", \"c\"]";

	private DefaultJsonObject cut;

	@BeforeEach
	public void setUp() {
		cut = createJsonParser(KEY_1, STRING_VALUE);
	}

	@Test
	public void contains_keyDoesExist_isTrue() {
		assertThat(cut.contains(KEY_1)).isTrue();
	}

	@Test
	public void contains_keyDoesNotExist_isFalse() {
		assertThat(cut.contains("doesNotExist")).isFalse();
	}

	@Test
	public void isEmpty() {
		assertThat(cut.isEmpty()).isFalse();
		assertThat(new DefaultJsonObject("{}").isEmpty()).isTrue();
	}

	@Test
	public void createWithmalformedJsonString_throwsException() {
		assertThatThrownBy(() -> new DefaultJsonObject("")).isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void getAsString_keyExists_returnsStringValue() {
		assertThat(cut.getAsString(KEY_1)).isEqualTo(STRING_TEXT);
	}

	@Test
	public void getAsString_keyDoesNotExists_returnsNull() {
		assertThat(cut.getAsString("keyDoesNotExist")).isNull();
	}

	@Test
	public void getAsString_keyDoesExistButTypeIsWrong_throwsException() {
		cut = createJsonParser(KEY_2, STRING_LIST_VALUE);

		assertThatThrownBy(() -> cut.getAsString(KEY_2)).isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void getAsListOfStrings_keyExists_returnsList() {
		cut = createJsonParser(KEY_2, STRING_LIST_VALUE);

		List<String> list = cut.getAsList(KEY_2, String.class);

		assertThat(list).hasSize(3).first().isEqualTo("a");
	}

	@Test
	public void getAsStringList_keyDoesExistButNoList_returnsList() {
		assertThat(cut.getAsString(KEY_1)).isEqualTo(STRING_TEXT);

		assertThat(cut.getAsStringList(KEY_1)).contains(STRING_TEXT);
		assertThat(cut.getAsStringList(KEY_1)).size().isEqualTo(1);

		assertThat(cut.getAsStringList(KEY_1)).size().isEqualTo(1);
	}

	@Test
	public void getAsStringList_keyExists_returnsList() {
		cut = createJsonParser(KEY_2, STRING_LIST_VALUE);

		List<String> list = cut.getAsStringList(KEY_2);

		assertThat(list).hasSize(3).first().isEqualTo("a");
	}

	@Test
	public void getAsListOfStrings_keyDoesNotExist_returnsEmptyList() {
		assertThat(cut.getAsList("keyDoesNotExist", String.class)).isEmpty();
	}

	@Test
	public void getAsListOfStrings_keyExistsButTypeIsWrong_throwsException() {
		cut = createJsonParser(KEY_2, STRING_LIST_VALUE);

		assertThatThrownBy(() -> cut.getAsList(KEY_2, Integer.class)).isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void getAsInstant_propertyExistsAndIsEpochTime_returnsInstant() {
		cut = createJsonParser(KEY_1, "\"" + FIRST_OF_APRIL.getEpochSecond() + "\"");

		Instant instant = cut.getAsInstant(KEY_1);

		assertThat(instant).isEqualTo(Instant.from(FIRST_OF_APRIL));
	}

	@Test
	public void getAsInstant_propertyExistsAndIsEpochTimeFormattedAsNumber_returnsInstant() {
		cut = createJsonParser(KEY_1, FIRST_OF_APRIL.getEpochSecond());

		Instant instant = cut.getAsInstant(KEY_1);

		assertThat(instant).isEqualTo(Instant.from(FIRST_OF_APRIL));
	}

	@Test
	public void getAsInstant_propertyDoesNotExist_returnsNull() {
		assertThat(cut.getAsInstant("keyDoesNotExist")).isNull();
	}

	@Test
	public void getAsInstant_propertyExistsButIsNotInEpochTime_throwsException() {
		assertThatThrownBy(() -> cut.getAsInstant(KEY_1))
				.isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void getAsLong_propertyExists_returnsValue() {
		cut = createJsonParser(KEY_1, 42);

		assertThat(cut.getAsLong(KEY_1)).isEqualTo(42);
	}

	@Test
	public void getAsLong_propertyExistsButIsNotANumber_throwsException() {
		cut = createJsonParser(KEY_1, "not a number");

		assertThatThrownBy(() -> cut.getAsLong(KEY_1))
				.isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void getJsonObject_propertyExists_returnsJsonObject() {
		cut = createJsonParser(KEY_1, createJsonObjectString(KEY_1, STRING_VALUE));

		JsonObject jsonObject = cut.getJsonObject(KEY_1);

		assertThat(jsonObject).isNotNull();
		assertThat(jsonObject.getAsString(KEY_1)).isNotNull();
	}

	@Test
	public void getJsonObjects_propertyExists_returnsJsonObjects() {
		cut = createJsonParser(KEY_1, "[" + createJsonObjectString(KEY_1, STRING_VALUE) + "]");

		List<JsonObject> jsonObjects = cut.getJsonObjects(KEY_1);

		assertThat(jsonObjects).isNotNull().hasSize(1);
		assertThat(jsonObjects.get(0).getAsString(KEY_1)).isNotNull();
	}

	@Test
	public void getJsonObject_propertyDoesNotExists_returnsNull() {
		JsonObject jsonObject = cut.getJsonObject("keyDoesNotExist");

		assertThat(jsonObject).isNull();
	}

	@Test
	public void getJsonObject_propertyExistsButIsNotAnObject_throwsException() {
		assertThatThrownBy(() -> cut.getJsonObject(KEY_1)).isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void getJsonObjects_propertyDoesNotExists_returnsEmptyList() {
		List<JsonObject> jsonObjects = cut.getJsonObjects("keyDoesNotExist");

		assertThat(jsonObjects).isEmpty();
	}

	@Test
	public void getJsonObjects_propertyExists_returnsEmptyList() {
		cut = createJsonParser(KEY_1, "[]");

		List<JsonObject> jsonObjects = cut.getJsonObjects(KEY_1);

		assertThat(jsonObjects).isNotNull().isEmpty();
	}

	@Test
	public void getJsonObjects_propertyExistsButIsNotAnArray_throwsException() {
		assertThatThrownBy(() -> cut.getJsonObjects(KEY_1)).isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void getJsonObject_propertyContainsEscapeChar() {
		String objectWithEscapeChars = "{\"iss\": \"https:\\/\\/subdomain.accounts400.ondemand.com\",\"key\": \"value\"}";
		DefaultJsonObject json = new DefaultJsonObject(objectWithEscapeChars);
		assertThat(json.getAsString("iss")).isEqualTo("https://subdomain.accounts400.ondemand.com");
		assertThat(json.getAsString("key")).isEqualTo("value");
	}

	// Test if affected by CVE https://nvd.nist.gov/vuln/detail/CVE-2022-45688
	// TODO: remove once org.json has released an updated version that fixes CVE
	@Test
	public void notVulnerableToStackOverflowException() {
		String deeplyNestedJsonObject = createDeeplyNestedJsonObjectString(100000);
		try {
			new DefaultJsonObject(deeplyNestedJsonObject);
		} catch (StackOverflowError e) {
			Assertions.fail("Encountered StackoverflowError.");
		} catch (Exception ignored) {
		}
	}

	private static String createDeeplyNestedJsonObjectString(int depth) {
		return "{" +
				// go down the JSON Object rabbit hole...
				"\"a\" : {".repeat(Math.max(0, depth)) +

				// ... and up again
				"}".repeat(Math.max(0, depth)) +

				"}";
	}

	private DefaultJsonObject createJsonParser(String key, Object value) {
		String jsonString = createJsonObjectString(key, value);
		return new DefaultJsonObject(jsonString);
	}

	private String createJsonObjectString(String key, Object value) {
		return String.format("{%s : %s}", key, value);
	}
}
