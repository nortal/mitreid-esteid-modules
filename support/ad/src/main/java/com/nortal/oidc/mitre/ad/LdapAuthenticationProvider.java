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

package com.nortal.oidc.mitre.ad;

import lombok.extern.slf4j.Slf4j;
import org.ldaptive.Credential;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.auth.AuthenticationRequest;
import org.ldaptive.auth.AuthenticationResponse;
import org.ldaptive.auth.Authenticator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Implemented using ldaptive to better support AD. Inspired by CAS support for ldap.
 * 
 * @author Aleksei Lissitsin
 */
@Slf4j
public class LdapAuthenticationProvider implements AuthenticationProvider {

  @Autowired
  private Authenticator authenticator;
  @Autowired
  private LdapUserDetailsService userDetailsService;

  public LdapUserDetailsService getUserDetailsService() {
    return userDetailsService;
  }

  public void setUserDetailsService(LdapUserDetailsService userDetailsService) {
    this.userDetailsService = userDetailsService;
  }

  public Authenticator getAuthenticator() {
    return authenticator;
  }

  public void setAuthenticator(Authenticator authenticator) {
    this.authenticator = authenticator;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
    String username = token.getName();
    String password = (String) token.getCredentials();

    AuthenticationRequest request =
            new AuthenticationRequest(username, new Credential(password), "mail", "sn", "name", "givenName");
    try {
      AuthenticationResponse response = authenticator.authenticate(request);
      if (response.getResult()) {
        LdapEntry ldapEntry = response.getLdapEntry();
        UserDetails userDetails = userDetailsService.loadUserDetails(username, ldapEntry);
        return new UsernamePasswordAuthenticationToken(userDetails.getUsername(),
                                                       password,
                                                       userDetails.getAuthorities());
      }
    } catch (LdapException e) {
      log.error("", e);
    }
    return null;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
  }

}
