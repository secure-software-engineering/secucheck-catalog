package secucheck.catalogSpecifications.FluentTQLSpecifications.SQLInjection.CWE89;

import secucheck.catalogSpecifications.FuentTQLRepositories.Sinks.SQLSinks;
import secucheck.catalogSpecifications.FuentTQLRepositories.Sources.ServletSources;
import secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import secucheck.InternalFluentTQL.dsl.MethodSelector;
import secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import secucheck.InternalFluentTQL.dsl.annotations.ImportAndProcessOnlyStaticFields;
import secucheck.InternalFluentTQL.dsl.annotations.InFlowParam;
import secucheck.InternalFluentTQL.dsl.annotations.OutFlowReturnValue;
import secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

/**
 * Internal FluentTQL specification for SQL-Injection in servlet application.
 *
 */
@FluentTQLSpecificationClass
@ImportAndProcessOnlyStaticFields(classList = {ServletSources.class, SQLSinks.class})
public class ServletSQLInjectionSpec implements FluentTQLUserInterface {
    /**
     * encodeForSQL is a OWASP sanitizer that encodes the SQL related data. Therefore, flow should go through this method to avoid vulnerability.
     */
    @InFlowParam(parameterID = {1})
    @OutFlowReturnValue
    public Method sanitizer = new MethodSelector("org.owasp.esapi.Encoder: java.lang.String encodeForSQL(org.owasp.esapi.codecs.Codec, java.lang.String)");

    /**
     * Returns the Internal FluentTQL specification
     *
     * @return Internal FluentTQL specification
     */
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("SQLiInServler")
                .from(ServletSources.servletSources)
                .notThrough(sanitizer)
                .to(SQLSinks.sqlSinks)
                .report("Servlet SQL-Injection - CWE89!!")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(myTF);

        return myFluentTQLSpecs;
    }
}
