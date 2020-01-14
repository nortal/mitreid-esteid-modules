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

import javax.security.auth.x500.X500Principal;
import ee.sk.digidoc.DigiDocException;
import ee.sk.utils.ConfigManager;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * @author <a href="mailto:toomas.parna@nortal.com">Toomas Pärna</a>
 */
public class IdCardAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
  public IdCardAuthenticationFilter() {
    super("/idlogin");
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
          throws AuthenticationException, IOException, ServletException {
    X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
    if (certs == null || certs.length == 0)
      return null;

    X509Certificate cert = certs[0];
    if (!validateCertificate(cert))
      throw new AccessDeniedException("Invalid certificate");

    PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(extractPrincipal(cert), cert);
    final Authentication authentication = getAuthenticationManager().authenticate(token);
    logger.debug("authentication : {" + authentication + "}");
    return authentication;
  }

  private Object extractPrincipal(X509Certificate cert) {
    String subjectPrincipal = cert.getSubjectX500Principal().getName(X500Principal.RFC1779);

    //String personCountry = getDnField(subjectPrincipal, COUNTRY_PATTERN, 1);
    String personCode = getDnField(subjectPrincipal, SN_PATTERN, 3);
    return personCode;
  }

  private Pattern SN_PATTERN = Pattern.compile(" CN=\"(.*?),(.*?),(.*?)\", ");
  private Pattern COUNTRY_PATTERN = Pattern.compile(" C=(.+),?");

  private String getDnField(String dn, Pattern pattern, int grp) {
    Matcher m = pattern.matcher(dn);
    if (!m.find())
      throw new IllegalArgumentException("Invalid DN format");
    return m.group(grp);
  }

  private boolean validateCertificate(X509Certificate cert) {
    try {
      @SuppressWarnings("deprecation")
      OCSPResp ocspr = ConfigManager.instance().getNotaryFactory().checkCertificate(cert);
      if (ocspr.getStatus() != OCSPResp.SUCCESSFUL) {
        logger.warn("Invalid id-card certificate detected: " + cert.getSubjectDN().toString());
        return false;
      }
      return true;
    } catch (DigiDocException dde) {
      logger.warn("Id-card certificate validation via jdigidoc failed with exception", dde);
      return false;
    }
  }
}
