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

import ee.sk.mid.MidAuthentication;
import ee.sk.mid.MidAuthenticationError;
import ee.sk.mid.MidAuthenticationHashToSign;
import ee.sk.mid.MidAuthenticationResponseValidator;
import ee.sk.mid.MidAuthenticationResult;
import ee.sk.mid.MidClient;
import ee.sk.mid.MidHashType;
import ee.sk.mid.MidInputUtil;
import ee.sk.mid.MidLanguage;
import ee.sk.mid.exception.MidInternalErrorException;
import ee.sk.mid.exception.MidInvalidNationalIdentityNumberException;
import ee.sk.mid.exception.MidInvalidPhoneNumberException;
import ee.sk.mid.exception.MidSessionNotFoundException;
import ee.sk.mid.rest.dao.MidSessionStatus;
import ee.sk.mid.rest.dao.request.MidAuthenticationRequest;
import ee.sk.mid.rest.dao.request.MidSessionStatusRequest;
import ee.sk.mid.rest.dao.response.MidAuthenticationResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;

import javax.annotation.PostConstruct;

import java.util.Date;
import java.util.List;

@Slf4j
class MobileIdService {
  
  @Value("${mid.service.url}")
  private String serviceUrl;
  
  @Value("${mid.service.name}")
  private String serviceName;
  
  @Value("${mid.service.uuid}")
  private String serviceUuid;
  
  private MidClient midClient;
  
  @PostConstruct
  private void init() {
    midClient = MidClient.newBuilder()
                  .withHostUrl(serviceUrl)
                  .withRelyingPartyUUID(serviceUuid)
                  .withRelyingPartyName(serviceName)
                  .build();
  }

  public MobileIdResult startAuthentication(String personCode, String phoneNr, MidLanguage language)
          throws MobileIdException {
    try {
      MidAuthenticationHashToSign authHash = MidAuthenticationHashToSign.generateRandomHashOfDefaultType();
      String verificationCode = authHash.calculateVerificationCode();

      MidAuthenticationRequest req =
              MidAuthenticationRequest.newBuilder()
                .withPhoneNumber(MidInputUtil.getValidatedPhoneNumber(phoneNr))
                .withHashToSign(authHash)
                .withNationalIdentityNumber(MidInputUtil.getValidatedNationalIdentityNumber(personCode))
                .withLanguage(language)
                .build();

      MidAuthenticationResponse res = midClient.getMobileIdConnector().authenticate(req);

      return MobileIdResult.builder()
              .timestamp(new Date())
              .userPhoneNr(phoneNr)
              .hash(authHash.getHashInBase64())
              .sessionId(res.getSessionID())
              .challengeId(verificationCode)
              .build();
      
    } catch (MidInternalErrorException e) {
      log.warn(e.getMessage());
      throw new MobileIdException(MobileIdFault.INTERNAL_ERROR, e);
    } catch (MidInvalidPhoneNumberException e) {
      throw new MobileIdException(MobileIdFault.INVALID_PHONE);
    } catch (MidInvalidNationalIdentityNumberException e) {
      throw new MobileIdException(MobileIdFault.INVALID_ID);
    }
  }

  public MobileIdResult checkAuthenticationStatus(MobileIdResult midResult) throws MobileIdException {
    try {
      MidSessionStatus sessionStatus =
              midClient.getMobileIdConnector().getAuthenticationSessionStatus(new MidSessionStatusRequest(midResult.getSessionId()));
      if (sessionStatus != null) {
        if (MobileIdStatus.RUNNING.is(sessionStatus.getState())) {
          return midResult.toBuilder().status(MobileIdStatus.RUNNING).build();
        }
        if (MobileIdStatus.COMPLETE.is(sessionStatus.getState())) {
          if (!MobileIdStatus.OK.is(sessionStatus.getResult())) {
            throw new MobileIdException(sessionStatus.getResult());
          }
          MidAuthentication authentication =
                  midClient.createMobileIdAuthentication(sessionStatus,
                                                         MidAuthenticationHashToSign.newBuilder().withHashInBase64(midResult.getHash()).withHashType(MidHashType.SHA256).build());
          MidAuthenticationResult result = new MidAuthenticationResponseValidator().validate(authentication);

          if (result.isValid()) {
            return midResult.toBuilder().status(MobileIdStatus.COMPLETE).identity(result.getAuthenticationIdentity()).build();
          } else {
            throw new MobileIdException(getAuthenticationError(result.getErrors()));
          }
        }
      }
      throw new MobileIdException(MobileIdFault.INTERNAL_ERROR);
    } catch (MidSessionNotFoundException e) {
      throw new MobileIdException(MobileIdFault.EXPIRED_TRANSACTION, e);
    } catch (MidInternalErrorException e) {
      log.warn(e.getMessage());
      throw new MobileIdException(MobileIdFault.INTERNAL_ERROR, e);
    }
  }
  
  private MobileIdFault getAuthenticationError(List<String> errors) {
    if (errors.get(0).equals(MidAuthenticationError.SIGNATURE_VERIFICATION_FAILURE.getMessage())) {
      return MobileIdFault.SIGNATURE_VERIFICATION_FAILURE;
    } else {
      return MobileIdFault.CERTIFICATE_EXPIRED;
    }
  }
}
