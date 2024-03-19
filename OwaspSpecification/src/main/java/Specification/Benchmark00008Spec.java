package Specification;

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
public class Benchmark00008Spec implements FluentTQLUserInterface {
    public Method source = new MethodConfigurator(
            "javax.servlet.http.HttpServletRequest: " +
                    "java.lang.String " +
                    "getHeader(java.lang.String)")
            .out().returnValue()
            .configure();

    public Method prop2 = new MethodConfigurator("java.sql.Connection: " +
            "java.sql.CallableStatement " +
            "prepareCall(java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public Method prop1 = new MethodConfigurator("java.net.URLDecoder: " +
            "java.lang.String " +
            "decode(java.lang.String,java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public Method sink = new MethodConfigurator(
            "java.sql.PreparedStatement: " +
                    "java.sql.ResultSet executeQuery()")
            .in().thisObject()
            .configure();

    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery taintFlow1 = new TaintFlowQueryBuilder("Benchmark00008")
                .from(source)
                .through(prop1)
                .through(prop2)
                .to(sink)
                .report("Benchmark00008 SQLi")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(taintFlow1);

        return myFluentTQLSpecs;
    }
}
