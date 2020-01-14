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
package com.nortal.oidc.mitre.idCard;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.mitre.openid.connect.model.DefaultUserInfo;

import com.nortal.oidc.mitre.base.DefaultUserInfoCreator;

class IdCardUserInfoCreator extends DefaultUserInfoCreator {

	private Pattern CN_PATTERN = Pattern.compile(" CN=\"(.*?),(.*?),(.*?)\", ");

	DefaultUserInfo createUserDetails(String username, X509Certificate cert) {
		DefaultUserInfo ui = new DefaultUserInfo();
		ui.setPreferredUsername(username);
		ui.setSub("ESTID::" + username);

		// TODO: check the name/ssn/email field mappings.
		Matcher cnMatcher = CN_PATTERN.matcher(cert.getSubjectX500Principal().getName(X500Principal.RFC1779));
		if (cnMatcher.find()) {
			ui.setFamilyName(cnMatcher.group(1));
			ui.setGivenName(cnMatcher.group(2));
			// String ssn = cnMatcher.group(3);// XXX: anywhere to stick person
			// code?
			ui.setName(ui.getGivenName() + " " + ui.getFamilyName());
		}
		ui.setEmail(getOfficialEmailFromIDCertificate(cert));
		return transform(ui);
	}

	private String getOfficialEmailFromIDCertificate(X509Certificate cert) {
		try {
			Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
			if (altNames.isEmpty())
				return null;
			return (String) altNames.iterator().next().get(1);
		} catch (CertificateParsingException e) {
			throw new RuntimeException(e);
		}
	}
}
