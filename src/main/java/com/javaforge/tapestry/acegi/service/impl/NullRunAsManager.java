package com.javaforge.tapestry.acegi.service.impl;

import java.util.Collection;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.core.Authentication;

public class NullRunAsManager implements RunAsManager {

    @Override
    public Authentication buildRunAs(Authentication arg0, Object arg1, Collection<ConfigAttribute> arg2) {
        return null;
    }

    @Override
    public boolean supports(ConfigAttribute arg0) {
        return false;
    }

    @Override
    public boolean supports(Class<?> klass) {
        return true;
    }

}
