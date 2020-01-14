/**
 *  Copyright 2020 Nortal AS
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */
package com.nortal.oidc.mitre.delegate;

import org.pac4j.core.client.Client;
import org.pac4j.core.client.Clients;
import org.pac4j.core.client.IndirectClient;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.exception.HttpAction;
import org.springframework.beans.factory.annotation.Autowired;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Inserts redirection urls for pac4j clients as attributes of a request.
 *
 * @author Aleksei Lissitsin
 */
public class Pac4jInterceptor extends LoginInterceptor {
  @Autowired
  private Clients clients;

  @Override
  @SuppressWarnings("rawtypes")
  public void intercept(HttpServletRequest request, HttpServletResponse response) {
    for (Client client : clients.findAllClients()) {
      if (client instanceof IndirectClient) {
        IndirectClient c = (IndirectClient) client;
        J2EContext context = new J2EContext(request, response);
        String redirectionUrl = getRedirectionUrl(c, context);
        request.setAttribute(c.getName() + "LoginUrl", redirectionUrl);
      }
    }
  }

  private String getRedirectionUrl(IndirectClient c, final WebContext context) {
    try {
      return c.getRedirectAction(context).getLocation();
    } catch (final HttpAction e) {
      return null;
    }
  }

}
