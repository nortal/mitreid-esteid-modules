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

import java.util.HashMap;
import java.util.Map;

/**
 * Mobiil id vigade koodid.
 * 
 * @author <a href="mailto:laurit@webmedia.ee">Lauri Tulmin</a> 22.06.2007
 */
public enum MobileIdFault {
  // teenust kasutava kliendi põhjustatud vead
  UNKNOWN("100"), // Teenuse üldine veasituatsioon
  INVALID_PHONE_NUMBER("101"), // Sisendparameetrid mittekorrektsel kujul
  MISSING_PARAMETERS("102"), // Mõni kohustuslik sisendparameeter on määramata
  RESTRICTED("103"), // Ligipääs antud meetodile antud parameetritega piiratud
  // teenusesisesed vead
  FAULT("200"), // Teenuse üldine viga
  USER_CERTIFICATE_MISSING("201"), // Kasutaja sertifikaat puudub
  UNABLE_TO_VERIFY_CERTIFICATE("202"), // Kasutaja sertifikaadi kehtivus ei ole võimalik kontrollida
  // lõppkasutaja ja tema telefoniga seotud vead
  PHONE_FAULT("300"), // Kasutajaga telefoniga seotud üldine viga
  NOT_MOBILE_ID_CLIENT("301"), // Pole Mobiil-ID kasutaja
  INVALID_CERTIFICATE("302"), // Kasutaja sertifikaat ei kehti (OCSP vastus REVOKED)
  UNKNOWN_CERTIFICATE("303"); // Kasutaja sertifikaadi olek teadmata (OCSP vastus UNKNOWN)

  private static final Map<String, MobileIdFault> types = new HashMap<String, MobileIdFault>();
  static {
    for (MobileIdFault c : MobileIdFault.values()) {
      types.put(c.getCode(), c);
    }
  }

  private final String code;

  private MobileIdFault(String code) {
    this.code = code;
  }

  public String getCode() {
    return code;
  }

  /**
   * @param code
   * @return antud koodile vastav viga või MobiilidViga.UNKNOWN kui antud koodile vastavat viga ei leitud.
   */
  public static MobileIdFault getFault(String code) {
    MobileIdFault viga = types.get(code);
    return viga != null ? viga : FAULT;
  }

}
