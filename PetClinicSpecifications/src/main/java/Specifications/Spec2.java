package Specifications;

import de.fraunhofer.iem.secucheck.fluenttql.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.MethodSelector;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.TaintFlowQueryBuilder;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.annotations.*;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.MethodPackage.Method;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

@FluentTQLSpecificationClass
public class Spec2 implements FluentTQLUserInterface {
    @OutFlowParam(parameterID = {0})
    public Method source = new MethodSelector("org.springframework.samples.petclinic.owner.OwnerController: " +
            "java.lang.String initUpdateOwnerForm(int,org.springframework.ui.Model)");

    @InFlowParam(parameterID = {0})
    @OutFlowReturnValue
    public Method requiredProp = new MethodSelector("javax.persistence.EntityManager: " +
            "javax.persistence.TypedQuery createQuery(java.lang.String,java.lang.Class)");

    @InFlowThisObject
    public Method sink = new MethodSelector("javax.persistence.TypedQuery: " +
            "java.lang.Object getSingleResult()");

    @Override
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery taintFlow = new TaintFlowQueryBuilder("h2")
                .from(source)
                .through(requiredProp)
                .to(sink)
                .report("H-Injection 2")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(taintFlow);

        return myFluentTQLSpecs;
    }
}
