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

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.factory.NotaryFactory;
import ee.sk.utils.ConfigManager;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import javax.annotation.PostConstruct;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;

/**
 * @author Priit Liivak
 */
public class JddConfigurationInitializer {
  private static final Logger log = LoggerFactory.getLogger(JddConfigurationInitializer.class);

  private NotaryFactory notary;

  public NotaryFactory getNotary() {
    return notary;
  }

  @Value("${esteid.jdigidoc.config}")
  private String jdigidocCfg;

  @PostConstruct
  void configureJDigiDoc() {
    log.info("Configuring JDigiDoc");
    Security.addProvider(new BouncyCastleProvider());

    if (ConfigManager.init(jdigidocCfg)) {
      log.info("JDigiDoc is initialized, configuring Notary...");
      try {
        this.notary = ConfigManager.instance().getNotaryFactory();
        log.info("Notary is initialized!");
      } catch (DigiDocException e) {
        log.error("Notary is not initialized! ID card athentication doesn't work!", e);
        throw new RuntimeException("Notary is not initialized! ID card athentication doesn't work!", e);
      }
    } else {
      log.error("\n\nJDigiDoc is not initialized! ID card athentication doesn't work!\n\n");
      // jdigidoc hides the exceptions, only logs some error info and returns false from init.
      // So throw our own exception on init failure.
      // throw new RuntimeException("JDigidoc is not initialized! ID card authentication doesn't work!");
    }

    try {
      MessageDigest.getInstance("SHA1", BouncyCastleProvider.PROVIDER_NAME);
    } catch (NoSuchAlgorithmException e1) {
      log.error("Provider initialization error", e1);
      throw new RuntimeException("Provider initialization error", e1);
    } catch (NoSuchProviderException e1) {
      log.error("Provider initialization error", e1);
      throw new RuntimeException("Provider initialization error", e1);
    }
  }

}
