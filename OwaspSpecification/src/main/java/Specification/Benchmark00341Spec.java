package Specification;

import Specification.FluentTQLRepositories.GeneralPropagators.Props;
import Specification.FluentTQLRepositories.GeneralPropagators.Sinks;
import Specification.FluentTQLRepositories.GeneralPropagators.Sources;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.TaintFlowQueryBuilder;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.annotations.FluentTQLSpecificationClass;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.MethodPackage.Method;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

@FluentTQLSpecificationClass
public class Benchmark00341Spec implements FluentTQLUserInterface {
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery taintFlow1 = new TaintFlowQueryBuilder("Benchmark00341")
                .from(Sources.source_00341)
                .through(Props.prop1_00341)
                .through(Props.prop2_00341)
                .to(Sinks.sink_00341)
                .report("Benchmark00341 SQLi")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(taintFlow1);

        return myFluentTQLSpecs;
    }
}
