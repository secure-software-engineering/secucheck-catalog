package Specifications;

import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodSelector;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodSet;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.*;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

@FluentTQLSpecificationClass
public class Spec5 implements FluentTQLUserInterface {
    @OutFlowParam(parameterID = {0})
    public Method source = new MethodSelector("org.springframework.samples.petclinic.owner.OwnerController: " +
            "String processCreationForm(" +
            "org.springframework.samples.petclinic.owner.Owner," +
            "org.springframework.validation.BindingResult)");

    @InFlowParam(parameterID = {0})
    public Method sink1 = new MethodSelector("javax.persistence.EntityManager: " +
            "Any merge(Any)");

    @InFlowParam(parameterID = {0})
    public Method sink2 = new MethodSelector("javax.persistence.EntityManager: " +
            "Unit persist(Any)");

    public MethodSet sinks = new MethodSet("CrossSiteForgerySinks")
            .addMethod(sink1)
            .addMethod(sink2);

    @Override
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery taintFlow = new TaintFlowQueryBuilder("h5")
                .from(source)
                .to(sinks)
                .report("H-Injection 5")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(taintFlow);

        return myFluentTQLSpecs;
    }
}
