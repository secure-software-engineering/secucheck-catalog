package secucheck.catalogSpecifications.FluentTQLSpecifications.OpenRedirectAttack.CWE601;

import secucheck.catalogSpecifications.FuentTQLRepositories.Sources.ServletSources;
import secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import secucheck.InternalFluentTQL.dsl.MethodSelector;
import secucheck.InternalFluentTQL.dsl.QueriesSet;
import secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import secucheck.InternalFluentTQL.dsl.annotations.*;
import secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

/**
 * Internal FluentTQL specification for Open-Redirect attack.
 *
 */
@FluentTQLSpecificationClass
@ImportAndProcessOnlyStaticFields(classList = {ServletSources.class})
public class OpenRedirectAttackSpec implements FluentTQLUserInterface {
    /**
     * Source 4
     */
    @OutFlowReturnValue
    public Method source4 = new MethodSelector("javax.servlet.http.HttpServletRequest: javax.servlet.RequestDispatcher getRequestDispatcher(java.lang.String)");
    /**
     * redirectTable is a simple redirection table that performs the whitelist input validation.
     */
    @InFlowParam(parameterID = {0})
    @OutFlowReturnValue
    public Method sanitizer = new MethodSelector("catalog.OpenRedirect.CWE601: java.lang.String redirectTable(java.lang.String)");

    /**
     * Sink 1
     */
    @InFlowParam(parameterID = {0})
    public Method sink1 = new MethodSelector("javax.servlet.http.HttpServletResponse: void sendRedirect(java.lang.String)");

    /**
     * Sink 2
     */
    @InFlowThisObject
    public Method sink2 = new MethodSelector("javax.servlet.RequestDispatcher: void forward(javax.servlet.ServletRequest, javax.servlet.ServletResponse)");

    /**
     * Returns the Internal FluentTQL specification
     *
     * @return Internal FluentTQL specification
     */
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery tf1 = new TaintFlowQueryBuilder("OpenRedirect_TF1")
                .from(ServletSources.servletSources)
                .notThrough(sanitizer)
                .to(sink1)
                .report("Open-Redirect - CWE601!")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        TaintFlowQuery tf2 = new TaintFlowQueryBuilder("OpenRedirect_TF2")
                .from(source4)
                .notThrough(sanitizer)
                .to(sink2)
                .report("Open-Redirect - CWE601!!!")
                .at(LOCATION.SOURCEANDSINK)
                .build();


        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(
                new QueriesSet("OpenRedirectAttack")
                        .addTaintFlowQuery(tf1)
                        .addTaintFlowQuery(tf2)
        );

        return myFluentTQLSpecs;
    }
}
