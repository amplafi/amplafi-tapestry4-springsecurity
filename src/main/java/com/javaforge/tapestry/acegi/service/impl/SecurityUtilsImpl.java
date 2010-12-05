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

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.logging.Log;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.annotation.SecuredAnnotationSecurityMetadataSource;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
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
    private RunAsManager runAsManager = new  NullRunAsManager();
    private AccessDecisionManager accessDecisionManager;
    private boolean alwaysReauthenticate = false;
    private SecuredAnnotationSecurityMetadataSource metadataSource = new SecuredAnnotationSecurityMetadataSource();
//----------------------------------------------------------------------------------------------------------------------
// SecurityUtils Implementation
//----------------------------------------------------------------------------------------------------------------------

    public void checkSecurity(Object object, Collection<ConfigAttribute> attr)
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

    public Collection<ConfigAttribute> createConfigAttributeDefinition(Class securedClass)
    {
        Annotation a = securedClass.getAnnotation(Secured.class);
        String[] attributeTokens = ((Secured) a).value();
        List<ConfigAttribute> attributes = new ArrayList<ConfigAttribute>(attributeTokens.length);
        
        for(String token : attributeTokens) {
            attributes.add(new SecurityConfig(token));
        }
        
        return attributes;
    }
    public Collection<ConfigAttribute> createConfigAttributeDefinition(Method securedMethod)
    {
        return metadataSource.getAttributes(securedMethod, null);
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

    public void setLog(Log log) {
        this.log = log;
    }

    public Log getLog() {
        return log;
    }
}
