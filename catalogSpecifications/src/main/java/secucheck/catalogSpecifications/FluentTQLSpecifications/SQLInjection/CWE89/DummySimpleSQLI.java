package secucheck.catalogSpecifications.FluentTQLSpecifications.SQLInjection.CWE89;

import secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import secucheck.InternalFluentTQL.dsl.MethodSelector;
import secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import secucheck.InternalFluentTQL.dsl.annotations.AnalysisEntryPoint;
import secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import secucheck.InternalFluentTQL.dsl.annotations.InFlowParam;
import secucheck.InternalFluentTQL.dsl.annotations.OutFlowReturnValue;
import secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

/**
 * Internal FluentTQL specification for simple SQL-Injection.
 *
 */
@FluentTQLSpecificationClass
public class DummySimpleSQLI implements FluentTQLUserInterface {
    /**
     * Source
     */
    @OutFlowReturnValue
    public Method source = new MethodSelector("java.util.Scanner: java.lang.String nextLine()");

    /**
     * Sink
     */
    @InFlowParam(parameterID = {0})
    public Method sink = new MethodSelector("java.sql.Statement: java.sql.ResultSet executeQuery(java.lang.String)");

    @AnalysisEntryPoint
    public Method entryPoint = new MethodSelector(
            "secucheck.InternalFluentTQL.catalog.SQLInjection.CWE89.SimpleSQLInjection: java.sql.ResultSet getEmployeeInformationWithoutSanitizer()"
    );

    /**
     * Returns the Internal FluentTQL specification
     *
     * @return Internal FluentTQL specification
     */
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("DummySimpleSQLi")
                .from(source)
                .to(sink)
                .report("There is a SQL Injection - CWE89!!!")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(myTF);

        return myFluentTQLSpecs;
    }
}
