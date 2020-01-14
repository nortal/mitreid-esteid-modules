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
package com.nortal.oidc.mitre.mobileId;

import java.util.Arrays;
import java.util.List;

import org.mitre.openid.connect.model.DefaultUserInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import com.nortal.oidc.mitre.base.JpaUserInfoSaveService;

/**
 * @author <a href="mailto:toomas.parna@nortal.com">Toomas Pärna</a>
 */
class MobileIdAuthProvider implements AuthenticationProvider {
  @Autowired
  private JpaUserInfoSaveService userInfoSaveService;
  @Autowired
  private MobileIdUserInfoCreator mobileIdUserInfoCreator;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    if (!(authentication instanceof PreAuthenticatedAuthenticationToken))
      return null;
    PreAuthenticatedAuthenticationToken token = (PreAuthenticatedAuthenticationToken) authentication;
    if (!(token.getCredentials() instanceof MobileIdResult))
      return null;

    String username = (String) token.getPrincipal();
    MobileIdResult midResult = (MobileIdResult) token.getCredentials();

    List<SimpleGrantedAuthority> roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"));
    PreAuthenticatedAuthenticationToken auth = new PreAuthenticatedAuthenticationToken(username, midResult, roles);
    auth.setDetails(createAndSaveUser(username, midResult));
    return auth;
  }

  private DefaultUserInfo createAndSaveUser(String username, MobileIdResult midResult) {
	DefaultUserInfo userInfo = mobileIdUserInfoCreator.createUserDetails(username, midResult);
	userInfoSaveService.merge(userInfo);
	return userInfo;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
