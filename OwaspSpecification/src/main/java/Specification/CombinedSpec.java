package Specification;

import Specification.FluentTQLRepositories.GeneralPropagators.Props;
import Specification.FluentTQLRepositories.GeneralPropagators.Sinks;
import Specification.FluentTQLRepositories.GeneralPropagators.Sources;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.MethodSet;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.TaintFlowQueryBuilder;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.annotations.FluentTQLSpecificationClass;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

@FluentTQLSpecificationClass
public class CombinedSpec implements FluentTQLUserInterface {
    public static MethodSet sources = new MethodSet("Sources");

    public static MethodSet props = new MethodSet("Props");

    public static MethodSet sinks = new MethodSet("Sinks");

    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        sinks.addMethod(Sinks.sink_8);
        sinks.addMethod(Sinks.sink_18_27);
        sinks.addMethod(Sinks.sink_24_37);
        sinks.addMethod(Sinks.sink_25);
        sinks.addMethod(Sinks.sink_26);
        sinks.addMethod(Sinks.sink_341);
        sinks.addMethod(Sinks.sink_32_33);
        sinks.addMethod(Sinks.sink_34);
        sinks.addMethod(Sinks.sink_38);
        sinks.addMethod(Sinks.sink_39);
        sinks.addMethod(Sinks.sink_43);
        props.addMethod(Props.prop_8A_18A_341A);
        props.addMethod(Props.prop_8B);
        props.addMethod(Props.prop_18B_341B_37A_38_39);
        props.addMethod(Props.prop_24A_37B);
        props.addMethod(Props.prop_32A_33A_34A);
        sources.addMethod(Sources.source_8);
        sources.addMethod(Sources.source_18_341);
        sources.addMethod(Sources.source_24_25_26_27_43);
        sources.addMethod(Sources.source_32_33_34);
        sources.addMethod(Sources.source_37_38_39);

        TaintFlowQuery taintFlow1 = new TaintFlowQueryBuilder("Benchmark")
                .from(sources)
                .through(props)
                .to(sinks)
                .report("Benchmark SQLi")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(taintFlow1);

        return myFluentTQLSpecs;
    }
}
