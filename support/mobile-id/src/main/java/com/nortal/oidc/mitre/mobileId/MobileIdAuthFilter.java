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

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.annotation.PostConstruct;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.Builder;
import lombok.extern.slf4j.Slf4j;

/**
 * @author <a href="mailto:toomas.parna@nortal.com">Toomas Pärna</a>
 */
@Slf4j
class MobileIdAuthFilter extends AbstractAuthenticationProcessingFilter {
  MobileIdAuthFilter() {
    super("/mobileId");
  }

  @Autowired
  private MobileIdService mobileIdService;

  @Value("${digidocservice.state.secret}")
  private String midSecret;

  private final ObjectMapper json = new ObjectMapper();
  private TextEncryptor encryptor;

  @PostConstruct
  void initKeys() throws GeneralSecurityException {
    encryptor = Encryptors.text(midSecret, "582afc01");

    // Make sure we have valid crypto environment and keys
    if (!"test".equals(encryptor.decrypt(encryptor.encrypt("test"))))
      log.error("MID data encryptor failure, make sure unlimited crypto policy is installed");
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
          throws AuthenticationException, IOException, ServletException {
    try {
      String midAction = request.getParameter("action");
      if ("start".equals(midAction)) {
        startMIDAuthentication(request, response);
        return null;
      } else if ("status".equals(midAction)) {
        checkMIDSessionStatus(request, response);
        return null;
      } else if ("finalize".equals(midAction)) {
        return finalizeAuthentication(request, response);
      } else {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        return null;
      }
    } catch (MobileIdException mide) {
      log.warn("", mide);
      writeResponse(response, MIDResult.builder()
              .status(mide.getError().name())
              .build());
      return null;
    }
  }

  private void startMIDAuthentication(HttpServletRequest request, HttpServletResponse response)
          throws MobileIdException, IOException {
    String personCode = request.getParameter("personCode");
    String phone = request.getParameter("phone");

    if (StringUtils.isBlank(personCode) && StringUtils.isBlank(phone)) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }

    personCode = StringUtils.trimToEmpty(personCode).replaceAll("\\s", "");
    phone = StringUtils.trimToEmpty(phone).replaceAll("\\s", "");
	if (phone.startsWith("+")) {
		phone = phone.substring(1);
	} else {
		if (!phone.matches("^372.*"))// XXX: include other MID supported country prefixes
			phone = "372" + phone;
	}

    MobileIdResult midResult = mobileIdService.startAuthentication("EE", personCode, phone, "EST");
    if (midResult.getStatus() == MobileIdStatus.OK) {
      writeResponse(response, MIDResult.builder()
              .status("OK")
              .challengeId(midResult.getChallengeId())
              .payload(encryptMIDData(midResult))
              .build());
      return;
    }

    writeResponse(response, MIDResult.builder()
            .status(midResult.getStatus().name())
            .build());

  }

  private void checkMIDSessionStatus(HttpServletRequest request, HttpServletResponse response) throws IOException,
          MobileIdException {
    MobileIdResult midResult = getPayloadData(request, response);
    if (midResult == null)
      return;

    MobileIdStatus status = mobileIdService.checkAuthenticationStatus(midResult.getSessionCode());
    writeResponse(response, MIDResult.builder()
            .status(status.getCode())
            .build());
  }

  private Authentication finalizeAuthentication(HttpServletRequest request, HttpServletResponse response)
          throws IOException {
    MobileIdResult midResult = getPayloadData(request, response);
    if (midResult == null)
      return null;

    //String principal = midResult.getUserCountry() + midResult.getUserIdCode();
    String principal = midResult.getUserIdCode();

    PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(principal, midResult);
    final Authentication authentication = getAuthenticationManager().authenticate(token);
    logger.debug("authentication : {" + authentication + "}");
    return authentication;
  }

  private MobileIdResult getPayloadData(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String payload = request.getParameter("payload");
    if (payload == null) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST);
      return null;
    }

    MobileIdResult midResult = decryptMIDData(payload);
    if (System.currentTimeMillis() - midResult.getTimestamp().getTime() > 5l * 60l * 1000l) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST);
      return null;
    }
    return midResult;
  }

  // ///////////
  // utils

  private String encryptMIDData(MobileIdResult midResult) {
    try {
      return encryptor.encrypt(json.writeValueAsString(midResult));
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  private MobileIdResult decryptMIDData(String payload) {
    try {
      return json.readValue(encryptor.decrypt(payload), MobileIdResult.class);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private <DATA> void writeResponse(HttpServletResponse resp, DATA data) {
    resp.setContentType("application/json");
    try {
      IOUtils.write(json.writeValueAsBytes(data), resp.getWriter());
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Builder
  @lombok.Value
  private static class MIDResult {
    private String status;
    private String challengeId;
    private String payload;
  }

}
