package de.fraunhofer.iem.secucheck.defaultValue.inConstructor;

import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodSelector;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.InFlowThisObject;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.OutFlowReturnValue;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.methodSignature.MethodSignatureBuilder;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.MethodSignature;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

@FluentTQLSpecificationClass
public class DefaultValueConstructorSpec implements FluentTQLUserInterface {
    public MethodSignature sourceSig = new MethodSignatureBuilder()
            .topLevelMember("Main", "de.fraunhofer.iem.secucheck.defaultValue.inConstructor")
            .returns("String")
            .named("getPersonAddress")
            .configure();

    @OutFlowReturnValue
    public Method source = new MethodSelector(sourceSig);

    public Method requiredProp = new MethodConfigurator(
            "de.fraunhofer.iem.secucheck.defaultValue.inConstructor.DummySinkClass: void <init>(String, String, String, String)")
            .in().param(0).param(1).param(2).param(3)
            .out().thisObject()
            .configure();

    @InFlowThisObject
    public Method sink = new MethodSelector(
            "de.fraunhofer.iem.secucheck.defaultValue.inConstructor.DummySinkClass: Unit printData()");

    @Override
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery spec = new TaintFlowQueryBuilder("DefaultValueConstructorSpec")
                .from(source)
                .through(requiredProp)
                .to(sink)
                .report("Dummy Injection in Default Value Constructor in Kotlin")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(spec);

        return myFluentTQLSpecs;
    }
}
