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

public enum MobileIdFault {
  //Rest API session completion statuses
  TIMEOUT,
  NOT_MID_CLIENT,
  USER_CANCELLED,
  SIGNATURE_HASH_MISMATCH,
  PHONE_ABSENT,
  DELIVERY_ERROR,
  SIM_ERROR,
  
  //Rest API authentication check outcomes
  SIGNATURE_VERIFICATION_FAILURE,
  CERTIFICATE_EXPIRED,

  //Other errors
  INTERNAL_ERROR,
  EXPIRED_TRANSACTION,
  CERTIFICATE_ERROR,
  CERTIFICATE_REVOKED,
  INVALID_PHONE,
  INVALID_ID,
}
