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

import org.ldaptive.LdapEntry;
import org.mitre.openid.connect.model.DefaultUserInfo;

import com.nortal.oidc.mitre.base.DefaultUserInfoCreator;

public class LdapUserInfoCreator extends DefaultUserInfoCreator {
	
	public DefaultUserInfo create(String username, LdapEntry entry) {
		DefaultUserInfo info = new DefaultUserInfo();
		
		info.setEmail(get(entry, "mail"));
		info.setFamilyName(get(entry, "sn"));
		info.setGivenName(get(entry, "givenName"));
		info.setName(get(entry, "name"));
		
		info.setPreferredUsername(username);
		info.setSub(username);
		return transform(info);
	}
	
	private String get(LdapEntry entry, String attribute){
		return entry.getAttribute(attribute).getStringValue();
	}
}
