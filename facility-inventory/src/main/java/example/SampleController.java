/*
 * Copyright 2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package example;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@RestController
public class SampleController {

	private static final Log LOG = LogFactory.getLog(SampleController.class);

	private final WebClient webClient;

	public SampleController(WebClient webClient) {
		this.webClient = webClient;
	}

	@GetMapping("requestStandingDesk")
	String resourceServer1(
			@RegisteredOAuth2AuthorizedClient("facility-inventory") OAuth2AuthorizedClient authorizedClient) {
		try {
			// @formatter:off
			String body = this.webClient
				.get()
				.uri("/healthInformation")
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.retrieve()
				.bodyToMono(String.class)
				.block();
			LOG.info("body = " + body);
			// @formatter:on
		}
		catch (Exception exception) {
			LOG.info("return false. ", exception);
			return "false";
		}
		LOG.info("return true.");
		return "true";
	}

}
