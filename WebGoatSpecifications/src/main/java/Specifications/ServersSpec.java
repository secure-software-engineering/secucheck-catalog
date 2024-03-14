package Specifications;

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
public class ServersSpec implements FluentTQLUserInterface {
    public Method source = new MethodConfigurator(
            "org.owasp.webgoat.sql_injection.mitigation.Servers: " +
                    "java.util.List " +
                    "sort(java.lang.String)")
            .out().param(0)
            .configure();

    public Method propagator = new MethodConfigurator(
            "java.sql.Connection: java.sql.PreparedStatement prepareStatement(java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public Method sink = new MethodConfigurator(
            "java.sql.PreparedStatement: java.sql.ResultSet executeQuery()")
            .in().thisObject()
            .configure();

    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery taintFlow = new TaintFlowQueryBuilder("Servers_SQLiWithPreparedStmt")
                .from(source)
                .through(propagator)
                .to(sink)
                .report("Webgoat application: Mitigation -> Server")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(taintFlow);

        return myFluentTQLSpecs;
    }
}
