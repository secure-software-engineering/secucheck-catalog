package de.fraunhofer.iem.secucheck.functionTypeInMethodSignature;

import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodSelector;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.InFlowParam;
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
public class FunctionTypeInMethodSignatureSpec implements FluentTQLUserInterface {
    public MethodSignature sourceSig = new MethodSignatureBuilder()
            .topLevelMember("FunctionTypeInMethodSignature", "de.fraunhofer.iem.secucheck.functionTypeInMethodSignature")
            .returns("String")
            .named("source")
            .parameter("() -> String")
            .configure();

    @OutFlowReturnValue
    public Method source = new MethodSelector(sourceSig);

    public MethodSignature requiredPropSig = new MethodSignatureBuilder()
            .topLevelMember("FunctionTypeInMethodSignature", "de.fraunhofer.iem.secucheck.functionTypeInMethodSignature")
            .returns("String")
            .named("propagate")
            .parameter("String", "(String, Boolean) -> String")
            .configure();

    public Method requiredProp = new MethodConfigurator(requiredPropSig)
            .in().param(0)
            .out().returnValue()
            .configure();

    public MethodSignature sanitizerSig = new MethodSignatureBuilder()
            .topLevelMember("FunctionTypeInMethodSignature", "de.fraunhofer.iem.secucheck.functionTypeInMethodSignature")
            .returns("String")
            .named("sanitize")
            .parameter("String", "(String) -> String")
            .configure();

    public Method sanitizer = new MethodConfigurator(sanitizerSig)
            .in().param(0)
            .out().returnValue()
            .configure();

    public MethodSignature sinkSig = new MethodSignatureBuilder()
            .topLevelMember("FunctionTypeInMethodSignature", "de.fraunhofer.iem.secucheck.functionTypeInMethodSignature")
            .returns("Unit")
            .named("sink")
            .parameter("String")
            .configure();

    @InFlowParam(parameterID = {0})
    public Method sink = new MethodSelector(sinkSig);

    @Override
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery spec = new TaintFlowQueryBuilder("KotlinFunctionTypeInMethodSignature")
                .from(source)
                .through(requiredProp)
                .notThrough(sanitizer)
                .to(sink)
                .report("Dummy Injection in method that contain Kotlin's function type")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(spec);

        return myFluentTQLSpecs;
    }
}
