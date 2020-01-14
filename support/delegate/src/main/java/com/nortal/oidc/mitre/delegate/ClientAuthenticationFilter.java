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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.pac4j.core.client.Client;
import org.pac4j.core.client.Clients;
import org.pac4j.core.client.IndirectClient;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.Pac4jConstants;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.core.util.CommonHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

/**
* ADAPTED FROM an old version of pac4j-spring-security.
*/
public final class ClientAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

  private static final Logger logger = LoggerFactory.getLogger(ClientAuthenticationFilter.class);

  private Clients clients;

  /**
   * Define the suffix url on which the filter will listen for HTTP requests.
   *
   * @param suffixUrl the suffix url
   */
  public ClientAuthenticationFilter(final String suffixUrl) {
      super(suffixUrl);
  }

  protected ClientAuthenticationFilter() {
      super("/callback");
  }

  @Override
  public void afterPropertiesSet() {
      super.afterPropertiesSet();
      CommonHelper.assertNotNull("clients", this.clients);
      this.clients.init();
  }
  
  public AuthenticationUserDetailsService<ClientAuthenticationToken> getUserDetailsService() {
	return userDetailsService;
}

public void setUserDetailsService(AuthenticationUserDetailsService<ClientAuthenticationToken> userDetailsService) {
	this.userDetailsService = userDetailsService;
}

public UserDetailsChecker getUserDetailsChecker() {
	return userDetailsChecker;
}

public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
	this.userDetailsChecker = userDetailsChecker;
}

private AuthenticationUserDetailsService<ClientAuthenticationToken> userDetailsService;
  
  private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

  @Override
  @SuppressWarnings({ "rawtypes", "unchecked" })
  public Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response)
          throws AuthenticationException, IOException, ServletException {

      // context
      final WebContext context = new J2EContext(request, response);

      // get the right client
      final Client client = this.clients.findClient(context);

      // get credentials
      Credentials credentials;
      UserProfile userProfile;
      try {
          credentials = client.getCredentials(context);
          userProfile = client.getUserProfile(credentials, context);
      } catch (final HttpAction e) {
          logger.info("Requires additionnal HTTP action", e);
          return null;
      } catch (CredentialsException ce) {
          throw new BadCredentialsException("Error retrieving credentials", ce);
      }

      logger.debug("credentials : {}", credentials);
      // if credentials/profile is null, return to the saved request url
      if (credentials == null) {
          context.setSessionAttribute(Pac4jConstants.REQUESTED_URL, "");
          context.setSessionAttribute(client.getName() + IndirectClient.ATTEMPTED_AUTHENTICATION_SUFFIX, "");
          getFailureHandler().onAuthenticationFailure(request, response, new BadCredentialsException("No credentials"));
          return null;
      }
      
      // by default, no authorities
      Collection<? extends GrantedAuthority> authorities = new ArrayList<>();
      // get user details and check them
      UserDetails userDetails = null;
      if (this.userDetailsService != null) {
          final ClientAuthenticationToken tmpToken = new ClientAuthenticationToken(credentials, client.getName(), context,
                  userProfile, null);
          userDetails = this.userDetailsService.loadUserDetails(tmpToken);
          logger.debug("userDetails: {}", userDetails);
          if (userDetails != null) {
              this.userDetailsChecker.check(userDetails);
              authorities = userDetails.getAuthorities();
              logger.debug("authorities: {}", authorities);
          }
      }
      
      // new token with credentials (like previously) and user profile and
      // authorities
      final ClientAuthenticationToken result = new ClientAuthenticationToken(credentials, client.getName(), context, userProfile,
              authorities, userDetails);
      result.setDetails(this.authenticationDetailsSource.buildDetails(request));
      logger.debug("result: {}", result);
      return result;
  }

  public Clients getClients() {
      return this.clients;
  }

  public void setClients(final Clients clients) {
      this.clients = clients;
  }
}