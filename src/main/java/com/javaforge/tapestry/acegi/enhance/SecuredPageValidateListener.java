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

import java.util.Collection;

import org.apache.tapestry.IPage;
import org.apache.tapestry.event.PageEvent;
import org.apache.tapestry.event.PageValidateListener;
import org.springframework.security.access.ConfigAttribute;

import com.javaforge.tapestry.acegi.service.SecurityUtils;

/**
 * @author James Carman
 */
public class SecuredPageValidateListener implements PageValidateListener
{
//----------------------------------------------------------------------------------------------------------------------
// Fields
//----------------------------------------------------------------------------------------------------------------------

    private SecurityUtils securityUtils;
    private Collection<ConfigAttribute> configAttributeDefinition;

//----------------------------------------------------------------------------------------------------------------------
// Static Methods
//----------------------------------------------------------------------------------------------------------------------

    public static void addTo(SecurityUtils securityUtils, IPage page)
    {
        final SecuredPageValidateListener securedPageValidateListener = new SecuredPageValidateListener(securityUtils, page);

        page.addPageValidateListener(securedPageValidateListener);
    }

//----------------------------------------------------------------------------------------------------------------------
// Constructors
//----------------------------------------------------------------------------------------------------------------------

    public SecuredPageValidateListener(SecurityUtils securityUtils, IPage page)
    {
        this.securityUtils = securityUtils;
        this.configAttributeDefinition = securityUtils.createConfigAttributeDefinition(page.getClass());
    }

//----------------------------------------------------------------------------------------------------------------------
// PageValidateListener Implementation
//----------------------------------------------------------------------------------------------------------------------

    public void pageValidate(PageEvent pageEvent)
    {
        securityUtils.checkSecurity(pageEvent.getPage(), configAttributeDefinition);
    }
}
