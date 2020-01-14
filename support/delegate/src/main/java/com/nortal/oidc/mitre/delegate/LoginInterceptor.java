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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

public abstract class LoginInterceptor extends HandlerInterceptorAdapter {

	private static final String DEFAULT_LOGIN_SERVLET_PATH = "/login";

	private String loginServletPath = DEFAULT_LOGIN_SERVLET_PATH;

	/**
	 * @param loginServletPath
	 *            ServletPath for which to insert data. Defaults to "/login".
	 */
	public void setLoginServletPath(String loginServletPath) {
		this.loginServletPath = loginServletPath;
	}

	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
			throws Exception {
		if (loginServletPath.equals(request.getServletPath())) {
			intercept(request, response);
		}

		return super.preHandle(request, response, handler);
	}

	public abstract void intercept(HttpServletRequest request, HttpServletResponse response);
}
