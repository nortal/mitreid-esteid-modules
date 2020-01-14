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
package com.nortal.oidc.mitre.base;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.mitre.openid.connect.model.DefaultUserInfo;
import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.repository.UserInfoRepository;
import org.mitre.util.jpa.JpaUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public class JpaUserInfoSaveService {
	
	@PersistenceContext
	private EntityManager manager;
	
	@Autowired
	private UserInfoRepository userInfoRepository; 
	
	@Transactional
	public UserInfo save(DefaultUserInfo userInfo){
		return JpaUtil.saveOrUpdate(null, manager, userInfo);
	}
	
	@Transactional
	public void merge(DefaultUserInfo userInfo) {
		DefaultUserInfo previousUserInfo = (DefaultUserInfo) userInfoRepository
				.getByUsername(userInfo.getPreferredUsername());
		if (previousUserInfo != null) {
			userInfo.setId(previousUserInfo.getId());
		}
		save(userInfo);
	}
}
