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

package com.javaforge.tapestry.acegi.enhance;

import java.lang.reflect.Method;
import java.util.Collection;

import org.apache.commons.logging.Log;
import org.apache.hivemind.Location;
import org.apache.hivemind.service.MethodSignature;
import org.apache.tapestry.annotations.MethodAnnotationEnhancementWorker;
import org.apache.tapestry.enhance.EnhancementOperation;
import org.apache.tapestry.spec.IComponentSpecification;
import org.springframework.security.access.ConfigAttribute;

import com.javaforge.tapestry.acegi.service.SecurityUtils;

/**
 * @author James Carman
 */
public class SecuredMethodEnhancementWorker implements MethodAnnotationEnhancementWorker
{
    private Log log;
//----------------------------------------------------------------------------------------------------------------------
// Fields
//----------------------------------------------------------------------------------------------------------------------

    private SecurityUtils securityUtils;

//----------------------------------------------------------------------------------------------------------------------
// MethodAnnotationEnhancementWorker Implementation
//----------------------------------------------------------------------------------------------------------------------

    @SuppressWarnings("unused")
    public void performEnhancement(EnhancementOperation op,
                                   IComponentSpecification spec,
                                   Method method,
                                   Location location)
    {
        getLog().debug("Securing method " + method + "...");
        final String securityUtilsField = op.addInjectedField("_$securityUtils", SecurityUtils.class, securityUtils);
        final Collection<ConfigAttribute> configAttributeDefinition = securityUtils.createConfigAttributeDefinition(method);
        final String configAttributeDefinitionField = op.addInjectedField("_$configAttributeDefinition", Collection.class, configAttributeDefinition);
        final StringBuffer methodBody = new StringBuffer("{\n");
        methodBody.append(securityUtilsField + ".checkSecurity(this," + configAttributeDefinitionField + ");\n");
        if (!method.getReturnType().equals(Void.TYPE))
        {
            methodBody.append("return ");
        }
        methodBody.append("super." + method.getName() + "($$);\n}");
        op.addMethod(method.getModifiers(), new MethodSignature(method), methodBody.toString(), location);
    }

//----------------------------------------------------------------------------------------------------------------------
// Getter/Setter Methods
//----------------------------------------------------------------------------------------------------------------------

    public void setSecurityUtils(SecurityUtils securityUtils)
    {
        this.securityUtils = securityUtils;
    }

    public void setLog(Log log) {
        this.log = log;
    }

    public Log getLog() {
        return log;
    }
}
