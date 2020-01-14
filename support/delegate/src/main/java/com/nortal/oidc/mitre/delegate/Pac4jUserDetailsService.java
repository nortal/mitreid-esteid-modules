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

import java.util.ArrayList;
import java.util.List;

import org.mitre.openid.connect.model.DefaultUserInfo;
import org.pac4j.core.profile.CommonProfile;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.nortal.oidc.mitre.base.JpaUserInfoSaveService;

public class Pac4jUserDetailsService implements AuthenticationUserDetailsService<ClientAuthenticationToken> {

  @Autowired
  private JpaUserInfoSaveService userInfoSaveService;

  @Autowired
  private Pac4jUserInfoCreator userInfoCreator;

  @Override
  public UserDetails loadUserDetails(ClientAuthenticationToken token)
      throws UsernameNotFoundException {
    List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
    authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

    DefaultUserInfo userInfo = userInfoCreator.create((CommonProfile) token.getUserProfile());
    userInfoSaveService.merge(userInfo);

    return new User(userInfo.getPreferredUsername(), "", authorities);
  }
}
