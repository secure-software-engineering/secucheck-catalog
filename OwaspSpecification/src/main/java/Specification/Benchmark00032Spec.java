package Specification;

import Specification.FluentTQLRepositories.GeneralPropagators.Props;
import Specification.FluentTQLRepositories.GeneralPropagators.Sinks;
import Specification.FluentTQLRepositories.GeneralPropagators.Sources;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.TaintFlowQueryBuilder;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.annotations.FluentTQLSpecificationClass;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

@FluentTQLSpecificationClass
public class Benchmark00032Spec implements FluentTQLUserInterface {
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery taintFlow1 = new TaintFlowQueryBuilder("Benchmark00032")
                .from(Sources.source_32_33_34)
                .through(Props.prop_32A_33A_34A)
                .to(Sinks.sink_32_33)
                .report("Benchmark00032 SQLi")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(taintFlow1);

        return myFluentTQLSpecs;
    }
}
