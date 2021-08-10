package Specifications;

import secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import secucheck.InternalFluentTQL.dsl.MethodConfigurator;
import secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

@FluentTQLSpecificationClass
public class SqlInjectionLesson8Spec implements FluentTQLUserInterface {
    public Method source1 = new MethodConfigurator(
            "org.owasp.webgoat.sql_injection.introduction.SqlInjectionLesson8: " +
                    "org.owasp.webgoat.assignments.AttackResult " +
                    "completed(java.lang.String,java.lang.String)")
            .out().param(0)
            .configure();

    public Method source2 = new MethodConfigurator(
            "org.owasp.webgoat.sql_injection.introduction.SqlInjectionLesson8: " +
                    "org.owasp.webgoat.assignments.AttackResult " +
                    "completed(java.lang.String,java.lang.String)")
            .out().param(1)
            .configure();

    public Method sink = new MethodConfigurator(
            "java.sql.Statement: java.sql.ResultSet executeQuery(java.lang.String)")
            .in().param(0)
            .configure();

    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery taintFlow1 = new TaintFlowQueryBuilder("SQLInjectionLesson8_TF1")
                .from(source1)
                .to(sink)
                .report("Webgoat application: Introduction -> SqlInjectionLesson8 TF1")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        TaintFlowQuery taintFlow2 = new TaintFlowQueryBuilder("SQLInjectionLesson8_TF2")
                .from(source2)
                .to(sink)
                .report("Webgoat application: Introduction -> SqlInjectionLesson8 TF2")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(taintFlow1);
        myFluentTQLSpecs.add(taintFlow2);

        return myFluentTQLSpecs;
    }
}
