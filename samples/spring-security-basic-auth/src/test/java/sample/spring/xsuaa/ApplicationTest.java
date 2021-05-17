/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.xsuaa;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(classes = Application.class)
@java.lang.SuppressWarnings("squid:S2699")
//test properties are provided with /resources/application.yml
public class ApplicationTest {

	@Test
	public void whenSpringContextIsBootstrapped_thenNoExceptions() {
	}
}