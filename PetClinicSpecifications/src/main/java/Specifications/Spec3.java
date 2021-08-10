package Specifications;

import secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import secucheck.InternalFluentTQL.dsl.MethodSelector;
import secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import secucheck.InternalFluentTQL.dsl.annotations.*;
import secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

@FluentTQLSpecificationClass
public class Spec3 implements FluentTQLUserInterface {
    @OutFlowParam(parameterID = {0})
    public Method source = new MethodSelector("org.springframework.samples.petclinic.owner.OwnerController: " +
            "java.lang.String processFindForm(" +
            "org.springframework.samples.petclinic.owner.Owner," +
            "org.springframework.validation.BindingResult," +
            "java.util.Map)");

    @InFlowParam(parameterID = {0})
    @OutFlowReturnValue
    public Method requiredProp = new MethodSelector("javax.persistence.EntityManager: " +
            "javax.persistence.TypedQuery createQuery(java.lang.String,java.lang.Class)");

    @InFlowThisObject
    @OutFlowReturnValue
    public Method requiredProp1 = new MethodSelector("org.springframework.samples.petclinic.model.Person: " +
            "java.lang.String getLastName()");

    @InFlowThisObject
    public Method sink = new MethodSelector("javax.persistence.TypedQuery: java.util.List getResultList()");

    @Override
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery taintFlow = new TaintFlowQueryBuilder("h3")
                .from(source)
                .through(requiredProp1)
                .through(requiredProp)
                .to(sink)
                .report("H-Injection 3")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(taintFlow);

        return myFluentTQLSpecs;
    }
}
