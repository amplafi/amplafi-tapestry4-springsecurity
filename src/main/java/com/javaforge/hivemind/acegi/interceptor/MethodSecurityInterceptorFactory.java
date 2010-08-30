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

package com.javaforge.hivemind.acegi.interceptor;

import java.util.List;

import org.apache.commons.proxy.Interceptor;
import org.apache.commons.proxy.ProxyFactory;
import org.apache.commons.proxy.interceptor.MethodInterceptorAdapter;
import org.apache.hivemind.InterceptorStack;
import org.apache.hivemind.ServiceInterceptorFactory;
import org.apache.hivemind.internal.Module;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.AccessDecisionManager;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.intercept.method.MethodDefinitionSource;
import org.springframework.security.intercept.method.MethodDefinitionSourceEditor;
import org.springframework.security.intercept.method.aopalliance.MethodSecurityInterceptor;

/**
 * @author James Carman
 */
public class MethodSecurityInterceptorFactory implements ServiceInterceptorFactory {
    private AccessDecisionManager accessDecisionManager;

    private AuthenticationManager authenticationManager;

    private ApplicationEventPublisher applicationEventPublisher;

    private ProxyFactory proxyFactory;

    @SuppressWarnings("unused")
    public final void createInterceptor(InterceptorStack stack, Module module,
            List parameters) {
        stack.push(proxyFactory.createInterceptorProxy(stack.peek(),
                createInterceptor(parameters), new Class[] { stack
                        .getServiceInterface() }));
    }

    protected Interceptor createInterceptor(List parameters) {
        final MethodSecurityInterceptor interceptor = new MethodSecurityInterceptor();
        interceptor.setAccessDecisionManager(accessDecisionManager);
        interceptor.setAuthenticationManager(authenticationManager);
        interceptor.setApplicationEventPublisher(applicationEventPublisher);
        MethodDefinitionSourceEditor editor = new MethodDefinitionSourceEditor();
        editor.setAsText((String) parameters.get(0));
        interceptor.setObjectDefinitionSource((MethodDefinitionSource) editor
                .getValue());
        return new MethodInterceptorAdapter(interceptor);
    }

    public void setAccessDecisionManager(
            AccessDecisionManager accessDecisionManager) {
        this.accessDecisionManager = accessDecisionManager;
    }

    public AccessDecisionManager getAccessDecisionManager() {
        return accessDecisionManager;
    }

    public void setAuthenticationManager(
            AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    public void setApplicationEventPublisher(
            ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    public ApplicationEventPublisher getApplicationEventPublisher() {
        return applicationEventPublisher;
    }
}
