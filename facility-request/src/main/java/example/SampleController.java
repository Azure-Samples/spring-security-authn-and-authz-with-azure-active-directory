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

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@Controller
public class SampleController {

	private final WebClient webClient;

	public SampleController(WebClient webClient) {
		this.webClient = webClient;
	}

	@GetMapping("/")
	String index() {
		return "index";
	}

	@GetMapping("/userInfo")
	String userInfo(Model model, OAuth2AuthenticationToken authentication) {
		model.addAttribute("body", "Hi, " + authentication.getPrincipal().getName());
		return "response";
	}

	@GetMapping("/requestStandingDesk")
	String AADResourceServer1AADResourceServer2(Model model,
			@RegisteredOAuth2AuthorizedClient("facility-request") OAuth2AuthorizedClient authorizedClient) {
		// @formatter:off
		String body = this.webClient
			.get()
			.uri("/requestStandingDesk")
			.attributes(oauth2AuthorizedClient(authorizedClient))
			.retrieve()
			.bodyToMono(String.class)
			.block();
		// @formatter:on
		model.addAttribute("body", "true".equals(body) ? "Request succeeded" : "Request failed");
		return "response";
	}

}
