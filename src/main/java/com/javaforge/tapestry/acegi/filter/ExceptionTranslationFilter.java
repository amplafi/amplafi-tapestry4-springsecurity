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

package com.javaforge.tapestry.acegi.filter;
import org.acegisecurity.*;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.ui.AbstractProcessingFilter;
import org.acegisecurity.ui.AccessDeniedHandler;
import org.acegisecurity.ui.AccessDeniedHandlerImpl;
import org.acegisecurity.ui.AuthenticationEntryPoint;
import org.acegisecurity.ui.savedrequest.SavedRequest;
import org.acegisecurity.util.PortResolver;
import org.acegisecurity.util.PortResolverImpl;
import org.apache.commons.logging.Log;
import org.apache.hivemind.ApplicationRuntimeException;
import org.apache.tapestry.BindingException;
import org.apache.tapestry.IRequestCycle;
import org.apache.tapestry.error.ExceptionPresenter;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author James Carman
 */
public class ExceptionTranslationFilter implements ExceptionPresenterFilter
{
    private Log log;
//----------------------------------------------------------------------------------------------------------------------
// Fields
//----------------------------------------------------------------------------------------------------------------------

    private HttpServletRequest request;
    private HttpServletResponse response;
    private AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();
    private AuthenticationEntryPoint authenticationEntryPoint;
    private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();
    private PortResolver portResolver = new PortResolverImpl();
    private boolean createSessionAllowed = true;

//----------------------------------------------------------------------------------------------------------------------
// ExceptionPresenterFilter Implementation
//----------------------------------------------------------------------------------------------------------------------

    public void presentException(IRequestCycle requestCycle, Throwable exception, ExceptionPresenter exceptionPresenter)
    {
        Throwable rootCause = exception;

        while (rootCause instanceof ServletException)
        {
            rootCause = exception.getCause();
        }

        if (rootCause instanceof BindingException)
        {
            rootCause = exception.getCause();
        }

        if (rootCause instanceof ApplicationRuntimeException)
        {
            rootCause = exception.getCause();
        }

        try
        {
            if (rootCause instanceof AuthenticationException)
            {
                if (getLog().isDebugEnabled())
                {
                    getLog().debug("Authentication exception occurred; redirecting to authentication entry point", exception);
                }

                sendStartAuthentication((AuthenticationException) exception);
            }
            else if (rootCause instanceof AccessDeniedException)
            {
                if (authenticationTrustResolver.isAnonymous(SecurityContextHolder.getContext().getAuthentication()))
                {
                    if (getLog().isDebugEnabled())
                    {
                        getLog().debug("Access is denied (user is anonymous); redirecting to authentication entry point",
                                exception);
                    }

                    sendStartAuthentication(new InsufficientAuthenticationException("Full authentication is required to access this resource"));
                }
                else
                {
                    if (getLog().isDebugEnabled())
                    {
                        getLog().debug("Access is denied (user is not anonymous); delegating to AccessDeniedHandler",
                                exception);
                    }

                    accessDeniedHandler.handle(request, response, (AccessDeniedException) exception);
                }
            }
            else
            {
                exceptionPresenter.presentException(requestCycle, exception);
            }
        }
        catch (ServletException e)
        {
            exceptionPresenter.presentException(requestCycle, e);
        }
        catch (IOException e)
        {
            exceptionPresenter.presentException(requestCycle, e);
        }
    }

//----------------------------------------------------------------------------------------------------------------------
// Getter/Setter Methods
//----------------------------------------------------------------------------------------------------------------------

    public AuthenticationEntryPoint getAuthenticationEntryPoint()
    {
        return authenticationEntryPoint;
    }

    public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint)
    {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    public AuthenticationTrustResolver getAuthenticationTrustResolver()
    {
        return authenticationTrustResolver;
    }

    public void setAuthenticationTrustResolver(AuthenticationTrustResolver authenticationTrustResolver)
    {
        this.authenticationTrustResolver = authenticationTrustResolver;
    }

    public PortResolver getPortResolver()
    {
        return portResolver;
    }

    public void setPortResolver(PortResolver portResolver)
    {
        this.portResolver = portResolver;
    }

    /**
     * If <code>true</code>, indicates that <code>SecurityEnforcementFilter</code> is permitted to store the
     * target URL and exception information in the <code>HttpSession</code> (the default). In situations where you do
     * not wish to unnecessarily create <code>HttpSession</code>s - because the user agent will know the failed URL,
     * such as with BASIC or Digest authentication - you may wish to set this property to <code>false</code>. Remember
     * to also set the {@link org.acegisecurity.context.HttpSessionContextIntegrationFilter#allowSessionCreation} to
     * <code>false</code> if you set this property to <code>false</code>.
     *
     * @return <code>true</code> if the <code>HttpSession</code> will be used to store information about the failed
     *         request, <code>false</code> if the <code>HttpSession</code> will not be used
     */
    public boolean isCreateSessionAllowed()
    {
        return createSessionAllowed;
    }

    public void setCreateSessionAllowed(boolean createSessionAllowed)
    {
        this.createSessionAllowed = createSessionAllowed;
    }

    public void setAccessDeniedHandler(AccessDeniedHandler accessDeniedHandler)
    {
        Assert.notNull(accessDeniedHandler, "AccessDeniedHandler required");
        this.accessDeniedHandler = accessDeniedHandler;
    }

    public void setResponse(HttpServletResponse response)
    {
        this.response = response;
    }

//----------------------------------------------------------------------------------------------------------------------
// Other Methods
//----------------------------------------------------------------------------------------------------------------------

    //~ Methods ========================================================================================================
    public void initialize() throws Exception
    {
        Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint must be specified");
        Assert.notNull(portResolver, "portResolver must be specified");
        Assert.notNull(authenticationTrustResolver, "authenticationTrustResolver must be specified");
    }

    protected void sendStartAuthentication(AuthenticationException reason) throws ServletException, IOException
    {
        SavedRequest savedRequest = new SavedRequest(request, portResolver);

        if (getLog().isDebugEnabled())
        {
            getLog().debug("Authentication entry point being called; SavedRequest added to Session: " + savedRequest);
        }

        if (createSessionAllowed)
        {
            // Store the HTTP request itself. Used by AbstractProcessingFilter
            // for redirection after successful authentication (SEC-29)
            request.getSession().setAttribute(AbstractProcessingFilter.ACEGI_SAVED_REQUEST_KEY, savedRequest);
        }

        // SEC-112: Clear the SecurityContextHolder's Authentication, as the
        // existing Authentication is no longer considered valid
        SecurityContextHolder.getContext().setAuthentication(null);

        authenticationEntryPoint.commence(request, response, reason);
    }

    public void setRequset(HttpServletRequest request)
    {
        this.request = request;
    }

    public void setLog(Log log) {
        this.log = log;
    }

    public Log getLog() {
        return log;
    }
}
