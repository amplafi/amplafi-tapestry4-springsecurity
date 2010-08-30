/*
 * Copyright (c) 2006, Carman Consulting, Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied. See the License for
 * the specific language governing permissions and limitations under the
 * License.
 */

package com.javaforge.tapestry.acegi.service.impl;

import java.lang.reflect.Method;

import org.apache.commons.logging.Log;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.AccessDecisionManager;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationCredentialsNotFoundException; 
import org.springframework.security.AuthenticationManager;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.RunAsManager;
import org.springframework.security.SpringSecurityMessageSource;
import org.springframework.security.annotation.Secured;
import org.springframework.security.context.SecurityContext;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.runas.NullRunAsManager;
import org.springframework.util.Assert;

import com.javaforge.tapestry.acegi.service.SecurityUtils;

/**
 * @author James Carman
 */
@SuppressWarnings("unchecked")
public class SecurityUtilsImpl implements SecurityUtils
{
    private Log log;
//----------------------------------------------------------------------------------------------------------------------
// Fields
//----------------------------------------------------------------------------------------------------------------------

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    private AuthenticationManager authenticationManager;
    private RunAsManager runAsManager = new NullRunAsManager();
    private AccessDecisionManager accessDecisionManager;
    private boolean alwaysReauthenticate = false;

//----------------------------------------------------------------------------------------------------------------------
// SecurityUtils Implementation
//----------------------------------------------------------------------------------------------------------------------

    public void checkSecurity(Object object, ConfigAttributeDefinition attr)
    {
        Assert.notNull(object, "Object was null");


        if (attr != null)
        {
            if (getLog().isDebugEnabled())
            {
                getLog().debug("Secure object: " + object.toString() + "; ConfigAttributes: " + attr.toString());
            }

            // We check for just the property we're interested in (we do
            // not call Context.validate() like the ContextInterceptor)
            if (SecurityContextHolder.getContext().getAuthentication() == null)
            {
                new AuthenticationCredentialsNotFoundException(messages.getMessage("AbstractSecurityInterceptor.authenticationNotFound",
                        "An Authentication object was not found in the SecurityContext"));
            }

            // Attempt authentication if not already authenticated, or user always wants reauthentication
            Authentication authenticated;

            SecurityContext ctx = SecurityContextHolder.getContext();

            if (ctx.getAuthentication() == null || !ctx.getAuthentication().isAuthenticated() || alwaysReauthenticate)
            {
                authenticated = this.authenticationManager.authenticate(SecurityContextHolder.getContext()
                            .getAuthentication());
 

                // We don't authenticated.setAuthentication(true), because each provider should do that
                if (getLog().isDebugEnabled())
                {
                    getLog().debug("Successfully Authenticated: " + authenticated.toString());
                }

                SecurityContextHolder.getContext().setAuthentication(authenticated);
            }
            else
            {
                authenticated = SecurityContextHolder.getContext().getAuthentication();

                if (getLog().isDebugEnabled())
                {
                    getLog().debug("Previously Authenticated: " + authenticated.toString());
                }
            }

            // Attempt authorization
            this.accessDecisionManager.decide(authenticated, object, attr);


            if (getLog().isDebugEnabled())
            {
                getLog().debug("Authorization successful");
            }

            // Attempt to run as a different user
            Authentication runAs = this.runAsManager.buildRunAs(authenticated, object, attr);

            if (runAs == null)
            {
                if (getLog().isDebugEnabled())
                {
                    getLog().debug("RunAsManager did not change Authentication object");
                }
            }
            else
            {
                if (getLog().isDebugEnabled())
                {
                    getLog().debug("Switching to RunAs Authentication: " + runAs.toString());
                }
                SecurityContextHolder.getContext().setAuthentication(runAs);
            }
        }
        else
        {
            if (getLog().isDebugEnabled())
            {
                getLog().debug("Public object - authentication not attempted");
            }
        }
    }

    public ConfigAttributeDefinition createConfigAttributeDefinition(Class securedClass)
    {
        return createConfigAttributeDefinition((Secured)securedClass.getAnnotation(Secured.class));
    }

    public ConfigAttributeDefinition createConfigAttributeDefinition(Method securedMethod)
    {
        return createConfigAttributeDefinition((Secured)securedMethod.getAnnotation(Secured.class));
    }

//----------------------------------------------------------------------------------------------------------------------
// Getter/Setter Methods
//----------------------------------------------------------------------------------------------------------------------

    public void setAccessDecisionManager(AccessDecisionManager accessDecisionManager)
    {
        this.accessDecisionManager = accessDecisionManager;
    }

    public void setAlwaysReauthenticate(boolean alwaysReauthenticate)
    {
        this.alwaysReauthenticate = alwaysReauthenticate;
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager)
    {
        this.authenticationManager = authenticationManager;
    }

    public void setMessages(MessageSourceAccessor messages)
    {
        this.messages = messages;
    }

    public void setRunAsManager(RunAsManager runAsManager)
    {
        this.runAsManager = runAsManager;
    }

//----------------------------------------------------------------------------------------------------------------------
// Other Methods
//----------------------------------------------------------------------------------------------------------------------

    private ConfigAttributeDefinition createConfigAttributeDefinition(Secured securityConfigs)
    {
        return new ConfigAttributeDefinition(securityConfigs.value());
    }

    public void setLog(Log log) {
        this.log = log;
    }

    public Log getLog() {
        return log;
    }
}
