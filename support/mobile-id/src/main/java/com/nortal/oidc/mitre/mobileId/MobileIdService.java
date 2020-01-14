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

import lombok.RequiredArgsConstructor;

import ee.sk.digidocservice.DigiDocService;
import ee.sk.digidocservice.DigiDocServicePortType;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Date;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import javax.annotation.PostConstruct;
import javax.xml.soap.Detail;
import javax.xml.ws.Holder;
import javax.xml.ws.soap.SOAPFaultException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;

/**
 * @author <a href="mailto:toomas.parna@nortal.com">Toomas Pärna</a>
 */
@Slf4j
class MobileIdService {
  private URL wsdl;

  @Value("${digidocservice.serviceName}")
  private String midServiceName;

  @PostConstruct
  void init() {
    try {
      wsdl = new URL("http://www.sk.ee/DigiDocService/DigiDocService_2_3.wsdl");
    } catch (MalformedURLException e) {
      log.error(e.getMessage(), e);
      throw new RuntimeException(e);
    }
    checkDigidocServiceConnection();

    if (midServiceName == null)
      throw new IllegalArgumentException("MID service name is required");
    log.info("MID using serviceName: {}", midServiceName);
  }

  private void checkDigidocServiceConnection() {
    Holder<String> srvName = new Holder<>();
    Holder<String> srvVersion = new Holder<>();
    Holder<String> srvLibName = new Holder<>();
    Holder<String> srvLibVersion = new Holder<>();
    getPort().getVersion(srvName, srvVersion, srvLibName, srvLibVersion);

    // lets make sure we can connect to digidocService
    log.info("Active digidocService version: {}/{}/{}/{}",
             srvName.value,
             srvVersion.value,
             srvLibName.value,
             srvLibVersion.value);
  }

  public MobileIdResult startAuthentication(String country, String personCode, String phoneNr, String language)
          throws MobileIdException {
    try {
      MidAuthResponseHolder resp = new MidAuthResponseHolder();
      String challenge = generateChallenge();
      getPort().mobileAuthenticate(personCode, country, phoneNr, language, midServiceName, "",
                                   challenge, "asynchClientServer", 0, true, false,

                                   // response data in holders
                                   resp.sessionCode,
                                   resp.status,
                                   resp.userIdCode,
                                   resp.userGivenName,
                                   resp.userSurname,
                                   resp.userCountry,
                                   resp.userCommonName,
                                   resp.userCertData,
                                   resp.challengeId,
                                   resp.challenge,
                                   resp.revocationData);

      MobileIdResult midResult = resp.toMidResult(phoneNr);
      if (midResult.getStatus() != MobileIdStatus.OK)
        throw new MobileIdException(MobileIdFault.FAULT, null);

      return midResult;
    } catch (SOAPFaultException sfe) {
      Detail sfdetail = sfe.getFault().getDetail();
      log.error(sfdetail.getTextContent(), sfe);
      throw new MobileIdException(MobileIdFault.getFault(sfe.getFault().getFaultString()), sfdetail.getTextContent(), sfe);
    }
  }

  private String generateChallenge() {
    Random r = new Random();
    return IntStream.range(0, 20)
            .map(idx -> r.nextInt(16))
            .mapToObj(Integer::toHexString)
            .collect(Collectors.joining());
  }

  @RequiredArgsConstructor
  private static class MidAuthResponseHolder {
    Holder<Integer> sessionCode = h();
    Holder<String> status = h(),
            userIdCode = h(),
            userGivenName = h(),
            userSurname = h(),
            userCountry = h(),
            userCommonName = h(),
            userCertData = h(),
            challengeId = h(),
            challenge = h(),
            revocationData = h()
            ;

    public MobileIdResult toMidResult(String userPhoneNr) {
      return MobileIdResult.builder()
              .sessionCode(sessionCode.value)
              .status(MobileIdStatus.getStatus(status.value))
              .challengeId(challengeId.value)
              .userCountry(userCountry.value)
              .userIdCode(userIdCode.value)
              .userGivenName(userGivenName.value)
              .userSurname(userSurname.value)
              .userPhoneNr(userPhoneNr)
              // .certificateData(userCertData.value)
              .timestamp(new Date())
              .build();
    }
  }

  public MobileIdStatus checkAuthenticationStatus(int sessionCode) throws MobileIdException {
    try {
      Holder<String> status = h(), signature = h();
      getPort().getMobileAuthenticateStatus(sessionCode, false, status, signature);
      return MobileIdStatus.getStatus(status.value);
    } catch (SOAPFaultException sfe) {
      Detail sfdetail = sfe.getFault().getDetail();
      log.error(sfdetail.getTextContent(), sfe);
      throw new MobileIdException(MobileIdFault.FAULT, sfdetail.getTextContent(), sfe);
    }
  }

  private DigiDocServicePortType getPort() {
    return new DigiDocService(wsdl).getDigiDocService();
  }

  private static <V> Holder<V> h() {
    return new Holder<V>();
  }
}
