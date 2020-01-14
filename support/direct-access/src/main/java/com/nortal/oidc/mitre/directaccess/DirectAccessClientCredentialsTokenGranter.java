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
package com.nortal.oidc.mitre.directaccess;

import java.util.ArrayList;
import java.util.List;

import org.mitre.openid.connect.model.DefaultUserInfo;
import org.mitre.openid.connect.repository.UserInfoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import com.nortal.oidc.mitre.base.JpaUserInfoSaveService;

import lombok.Setter;

@Setter
public class DirectAccessClientCredentialsTokenGranter extends AbstractTokenGranter {
    
    @Autowired
    private UserInfoRepository userInfoRepository;
    
    @Autowired
    private JpaUserInfoSaveService userInfoSaveService;
    
    private DirectAccessUserinfoCreator userinfoCreator;

    protected DirectAccessClientCredentialsTokenGranter(AuthorizationServerTokenServices tokenServices,
            ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory) {
        super(tokenServices, clientDetailsService, requestFactory, "client_credentials");
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        OAuth2Request oAuth2Request = getRequestFactory().createOAuth2Request(client, tokenRequest);
        DefaultUserInfo userInfo = userinfoCreator.create(client, tokenRequest);
        if (userInfoRepository.getByUsername(userInfo.getPreferredUsername()) == null){
            userInfoSaveService.save(userInfo);
        }
        
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        
        return new OAuth2Authentication(oAuth2Request, new UsernamePasswordAuthenticationToken(userInfo.getSub(), "", authorities));
    }
}
