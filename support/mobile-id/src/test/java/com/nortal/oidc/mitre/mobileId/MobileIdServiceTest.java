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

import java.util.Properties;
import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.AbstractJUnit4SpringContextTests;

/**
 * @author <a href="mailto:toomas.parna@nortal.com">Toomas Pärna</a>
 */
@Slf4j
// XXX: this connects to the actual digidocservice, so can't keep it active as a unit-test
@Ignore
@ContextConfiguration
public class MobileIdServiceTest extends AbstractJUnit4SpringContextTests {
  @Autowired
  private MobileIdService midService;

  @Test
  public void testMidAuthentication() throws InterruptedException {
    try {
      // TODO: don't leave this test active with actual phone numbers in it...
      String country = "EE";
      String personCode = "";
      String phoneNr = "";
      // String language = "EST";
      String language = "ENG";

      // initialize the authentication process. Returns user info immediately.
      MobileIdResult auth = midService.startAuthentication(country, personCode, phoneNr, language);
      Assert.assertNotNull(auth);
      Assert.assertEquals("TOOMAS", auth.getUserGivenName());

      // wait for a bit before starting to check authentication process status
      Thread.sleep(10000);

      MobileIdStatus status;
      do {
        Thread.sleep(5000);
        // check for status until not in outstanding transaction state
        status = midService.checkAuthenticationStatus(auth.getSessionCode());
      } while (status == MobileIdStatus.OUTSTANDING_TRANSACTION);

      // if we got user_authenticated status, auth succeeded and we can consider user authenticated.
      if (status == MobileIdStatus.USER_AUTHENTICATED) {
        log.info("Authentication successful for user: {} {}/{}",
                 auth.getUserGivenName(),
                 auth.getUserSurname(),
                 auth.getUserIdCode());
      } else {
        log.info("Authentication failed with status: {}", status);
      }
    } catch (MobileIdException e) {
      log.error("", e);
      Assert.fail();
    }
  }

  @Configuration
  static class Cfg {
    @Bean
    static PropertySourcesPlaceholderConfigurer propertyPlaceholderConfigurer() {
      PropertySourcesPlaceholderConfigurer propCfg = new PropertySourcesPlaceholderConfigurer();
      Properties props = new Properties();
      props.setProperty("digidocservice.serviceName", "Arvekeskus");
      propCfg.setProperties(props);
      return propCfg;
    }

    @Bean
    MobileIdService mobileIdService() {
      return new MobileIdService();
    }
  }
  
  public boolean check(String phone) {
	  return phone.matches("^372.*");
  }
  
  @Test
  public void testRegexp() {
	  Assert.assertTrue(check("37255622274"));
	  Assert.assertFalse(check("55622274"));
	  Assert.assertFalse(check("+37255622274"));
  }
}
