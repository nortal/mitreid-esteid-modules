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

import lombok.Getter;

/**
 * Mobiilid autentimine ebaõnnestus.
 * 
 * @author <a href="mailto:laurit@webmedia.ee">Lauri Tulmin</a> 22.06.2007
 */
@Getter
public class MobileIdException extends Exception {
  private static final long serialVersionUID = 1L;

  private MobileIdFault error;
  private String faultDetail;

  public MobileIdException(MobileIdFault error, Throwable t) {
    this(error, null, t);
  }

  public MobileIdException(MobileIdFault error, String faultDetail, Throwable t) {
    super(t);
    this.error = error;
    this.faultDetail = faultDetail;
  }
}
