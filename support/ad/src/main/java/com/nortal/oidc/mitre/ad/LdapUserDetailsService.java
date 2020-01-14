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

import java.util.ArrayList;
import java.util.List;

import org.ldaptive.LdapEntry;
import org.mitre.openid.connect.model.DefaultUserInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.nortal.oidc.mitre.base.JpaUserInfoSaveService;

@Service("ldapUserDetailsService")
public class LdapUserDetailsService{
	
	@Autowired
	private JpaUserInfoSaveService userInfoSaveService;
	
	@Autowired
	private LdapUserInfoCreator ldapUserInfoCreator;

	public UserDetails loadUserDetails(String username, LdapEntry entry) {
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
		
		DefaultUserInfo userInfo = ldapUserInfoCreator.create(username, entry);
		userInfoSaveService.merge(userInfo);
		
		return new User(userInfo.getSub(), "", authorities);
	}
}
