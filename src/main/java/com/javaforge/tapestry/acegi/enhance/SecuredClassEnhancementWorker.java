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

import com.javaforge.tapestry.acegi.service.SecurityUtils;

import org.apache.commons.logging.Log;
import org.apache.hivemind.Location;
import org.apache.tapestry.IComponent;
import org.apache.tapestry.IPage;
import org.apache.tapestry.annotations.ClassAnnotationEnhancementWorker;
import org.apache.tapestry.enhance.EnhanceUtils;
import org.apache.tapestry.enhance.EnhancementOperation;
import org.apache.tapestry.spec.IComponentSpecification;

/**
 * @author James Carman
 */
public class SecuredClassEnhancementWorker implements
        ClassAnnotationEnhancementWorker {
    private Log log;

    // ----------------------------------------------------------------------------------------------------------------------
    // Fields
    // ----------------------------------------------------------------------------------------------------------------------

    private SecurityUtils securityUtils;

    @SuppressWarnings("unused")
    public void performEnhancement(EnhancementOperation op,
            IComponentSpecification spec, Class clazz, Location location) {
        if (op.implementsInterface(IPage.class)) {
            getLog().debug("Securing page class " + clazz.getName() + "...");
            final String securityUtilsField = op.addInjectedField(
                    "_$securityUtils", SecurityUtils.class, securityUtils);
            op.extendMethodImplementation(IComponent.class,
                    EnhanceUtils.FINISH_LOAD_SIGNATURE,
                    "com.javaforge.tapestry.acegi.enhance.SecuredPageValidateListener.addTo("
                            + securityUtilsField + ", this);");
        }
    }

    // ----------------------------------------------------------------------------------------------------------------------
    // Getter/Setter Methods
    // ----------------------------------------------------------------------------------------------------------------------

    public void setSecurityUtils(SecurityUtils securityUtils) {
        this.securityUtils = securityUtils;
    }

    public void setLog(Log log) {
        this.log = log;
    }

    public Log getLog() {
        return log;
    }
}
