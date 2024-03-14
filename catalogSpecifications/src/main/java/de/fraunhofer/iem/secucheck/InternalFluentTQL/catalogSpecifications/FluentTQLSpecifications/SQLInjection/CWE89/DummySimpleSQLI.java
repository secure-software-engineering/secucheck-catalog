package de.fraunhofer.iem.secucheck.InternalFluentTQL.catalogSpecifications.FluentTQLSpecifications.SQLInjection.CWE89;

import de.fraunhofer.iem.secucheck.fluenttql.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.MethodSelector;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.TaintFlowQueryBuilder;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.annotations.AnalysisEntryPoint;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.annotations.FluentTQLSpecificationClass;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.annotations.InFlowParam;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.annotations.OutFlowReturnValue;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.MethodPackage.Method;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

/**
 * Internal FluentTQL specification for simple SQL-Injection.
 *
 * @author Ranjith Krishnamurthy
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
            "de.fraunhofer.iem.secucheck.InternalFluentTQL.catalog.SQLInjection.CWE89.SimpleSQLInjection: java.sql.ResultSet getEmployeeInformationWithoutSanitizer()"
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
