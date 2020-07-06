/*******************************************************************************
 * Copyright 2015 WSO2 Inc. (http://wso2.org)
 *  
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *   
 *  http://www.apache.org/licenses/LICENSE-2.0
 *   
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package org.wso2.carbon.identity.application.authenticator.social.naver.internal;

import java.util.Hashtable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.social.naver.NaverCustomAuthenticator;

@Component(name = "NaverAuthenticatorServiceComponent",
immediate = true)
public class NaverAuthenticatorServiceComponent{

	private static final Log logger = LogFactory.getLog(NaverAuthenticatorServiceComponent.class);

	@Activate
 protected void activate(ComponentContext ctxt) {
        try {
        	NaverCustomAuthenticator naverAuthenticator = new NaverCustomAuthenticator();
            Hashtable<String, String> props = new Hashtable<String, String>();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),naverAuthenticator, props);
            logger.info("----Naver Authenticator bundle is activated----");
  
        } catch (Throwable e) {
            logger.fatal("----Error while activating Naver authenticator----", e);
        }
    }
  
	@Deactivate
	protected void deactivate(ComponentContext ctxt) {
        logger.info("----Naver Authenticator bundle is deactivated----");
    }

}
