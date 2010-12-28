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

import java.util.List;

import javax.servlet.Filter;

import com.javaforge.tapestry.acegi.filter.ServletRequestServicerFilterAdapter;

import org.apache.hivemind.ErrorLog;
import org.apache.hivemind.Location;
import org.apache.hivemind.ServiceImplementationFactory;
import org.apache.hivemind.ServiceImplementationFactoryParameters;
import org.apache.hivemind.impl.BaseLocatable;
import org.apache.hivemind.lib.DefaultImplementationBuilder;
import org.apache.hivemind.lib.pipeline.PipelineAssembler;
import org.apache.hivemind.lib.pipeline.PipelineContribution;
import org.apache.hivemind.lib.pipeline.PipelineParameters;
import org.apache.hivemind.service.ClassFactory;
import org.apache.tapestry.services.ServletRequestServicerFilter;

/**
 * @author James Carman
 */
public class ServletRequestServicerPipelineFactory extends BaseLocatable implements ServiceImplementationFactory
{
    private DefaultImplementationBuilder defaultImplementationBuilder;
    private ClassFactory classFactory;
    private ErrorLog errorLog;

    @SuppressWarnings("unchecked")
    public Object createCoreServiceImplementation(ServiceImplementationFactoryParameters factoryParameters)
    {
        PipelineParameters pp = (PipelineParameters) factoryParameters.getParameters().get(0);

        PipelineAssembler pa = new ServletFilterAwarePipelineAssembler(errorLog, factoryParameters.getServiceId(),
                factoryParameters.getServiceInterface(), pp.getFilterInterface(), classFactory,
                defaultImplementationBuilder);

        Object terminator = pp.getTerminator();

        if (terminator != null)
        {
            pa.setTerminator(terminator, pp.getLocation());
        }

        for(PipelineContribution c:(List<PipelineContribution>)pp.getPipelineConfiguration())
        {
            c.informAssembler(pa);
        }

        return pa.createPipeline();
    }

    public void setDefaultImplementationBuilder(DefaultImplementationBuilder defaultImplementationBuilder)
    {
        this.defaultImplementationBuilder = defaultImplementationBuilder;
    }

    public void setClassFactory(ClassFactory classFactory)
    {
        this.classFactory = classFactory;
    }

    public void setErrorLog(ErrorLog errorLog)
    {
        this.errorLog = errorLog;
    }

    private static class ServletFilterAwarePipelineAssembler extends PipelineAssembler
    {
        public ServletFilterAwarePipelineAssembler(ErrorLog errorLog, String string, Class<?> aClass, Class<?> aClass1, ClassFactory classFactory, DefaultImplementationBuilder defaultImplementationBuilder)
        {
            super(errorLog, string, aClass, aClass1, classFactory, defaultImplementationBuilder);
        }

        @Override
        public void addFilter(String name, String prereqs, String postreqs, Object filter, Location location)
        {
            if ((filter instanceof Filter) && !(filter instanceof ServletRequestServicerFilter))
            {
                super.addFilter(name, prereqs, postreqs, new ServletRequestServicerFilterAdapter((Filter) filter), location);
            }
            else
            {
                super.addFilter(name, prereqs, postreqs, filter, location);
            }
        }
    }
}
