/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.local.auth.emailotp.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.identity.local.auth.emailotp.EmailOTPAuthenticator;
import org.wso2.carbon.identity.local.auth.emailotp.EmailOTPExecutor;
import org.wso2.carbon.identity.local.auth.emailotp.connector.EmailOTPAuthenticatorConfigImpl;
import org.wso2.carbon.identity.user.registration.engine.graph.Executor;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Email OTP service component.
 */
@Component(
        name = "identity.local.auth.email.otp.component",
        immediate = true
)
public class AuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(AuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            BundleContext bundleContext = context.getBundleContext();
            bundleContext.registerService(IdentityConnectorConfig.class.getName(),
                    new EmailOTPAuthenticatorConfigImpl(), null);
            bundleContext.registerService(ApplicationAuthenticator.class.getName(),
                    new EmailOTPAuthenticator(), null);
            bundleContext.registerService(Executor.class.getName(), new EmailOTPExecutor(), null);
            if (log.isDebugEnabled()) {
                log.debug("Email OTP authenticator is activated");
            }
        } catch (Throwable e) {
            log.error("Error while activating the Email OTP authenticator", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("Email OTP authenticator is deactivated");
        }
    }

    @Reference(
            name = "RealmService",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        AuthenticatorDataHolder.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        AuthenticatorDataHolder.setRealmService(null);
    }

    @Reference(
            name = "AccountLockService",
            service = org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAccountLockService"
    )
    protected void setAccountLockService(AccountLockService accountLockService) {

        AuthenticatorDataHolder.setAccountLockService(accountLockService);
    }

    protected void unsetAccountLockService(AccountLockService accountLockService) {

        AuthenticatorDataHolder.setAccountLockService(null);
    }

    @Reference(
            name = "IdentityGovernanceService",
            service = org.wso2.carbon.identity.governance.IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService")
    protected void setIdentityGovernanceService(IdentityGovernanceService idpManager) {

        AuthenticatorDataHolder.setIdentityGovernanceService(idpManager);
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService idpManager) {

        AuthenticatorDataHolder.setIdentityGovernanceService(null);
    }

    @Reference(
            name = "EventMgtService",
            service = org.wso2.carbon.identity.event.services.IdentityEventService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityEventService")
    protected void setIdentityEventService(IdentityEventService eventService) {

        AuthenticatorDataHolder.setIdentityEventService(eventService);
    }

    protected void unsetIdentityEventService(IdentityEventService eventService) {

        AuthenticatorDataHolder.setIdentityEventService(null);
    }

    @Reference(
            name = "claim.meta.mgt.service",
            service = ClaimMetadataManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetClaimMetaMgtService")
    protected void setClaimMetaMgtService(ClaimMetadataManagementService claimMetaMgtService) {

        AuthenticatorDataHolder.setClaimMetadataManagementService(claimMetaMgtService);
    }

    protected void unsetClaimMetaMgtService(ClaimMetadataManagementService claimMetaMgtService) {

        AuthenticatorDataHolder.setClaimMetadataManagementService(null);
    }

    @Reference(
            name = "org.wso2.carbon.idp.mgt.IdpManager",
            service = IdpManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityProviderManagementService"
    )
    protected void setIdentityProviderManagementService(IdpManager idpManager) {

        AuthenticatorDataHolder.setIdpManager(idpManager);
    }

    protected void unsetIdentityProviderManagementService(IdpManager idpManager) {

        AuthenticatorDataHolder.setIdpManager(null);
    }
}
