package de.fraunhofer.iem.secucheck.dataTypeTransformer;

import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
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
public class DataTypeTransformerSpec implements FluentTQLUserInterface {
    @OutFlowReturnValue
    public Method source = new MethodSelector(
            "de.fraunhofer.iem.secucheck.dataTypeTransformer.classLevel.DummySource: " +
                    "String generateSecret(Int, kotlin.String, List)"
    );

    @InFlowParam(parameterID = {0})
    @OutFlowReturnValue
    public Method requiredProp = new MethodSelector(
            "de.fraunhofer.iem.secucheck.dataTypeTransformer.classLevel.DummySource: " +
                    "String propagateEverything(String)"
    );

    MethodSignature sinkSig = new MethodSignatureBuilder()
            .topLevelMember("DummySink", "de.fraunhofer.iem.secucheck.dataTypeTransformer.topLevel")
            .returns("Unit")
            .named("revealSecret")
            .parameter("String?", "Boolean")
            .configure();

    @InFlowParam(parameterID = {0})
    public Method sink = new MethodSelector(sinkSig);

    MethodSignature sanitizerSig = new MethodSignatureBuilder()
            .topLevelMember("DummySink", "de.fraunhofer.iem.secucheck.dataTypeTransformer.topLevel")
            .returns("String")
            .named("sanitizeSecret")
            .parameter("String")
            .configure();

    @InFlowParam(parameterID = {0})
    @OutFlowReturnValue
    public Method sanitizer = new MethodSelector(sanitizerSig);

    @Override
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery spec = new TaintFlowQueryBuilder("DataTypeTransformerSpec")
                .from(source)
                .notThrough(sanitizer)
                .through(requiredProp)
                .to(sink)
                .report("Dummy vulnerability in data type transformer in Kotlin")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(spec);

        return myFluentTQLSpecs;
    }
}
