package secucheck.catalogSpecifications.FluentTQLSpecifications.XSS.CWE79;

import secucheck.catalogSpecifications.FuentTQLRepositories.Sinks.ServletSinks;
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
 * Internal FluentTQL specification for Reflexive-XSS.
 *
 */
@FluentTQLSpecificationClass
@ImportAndProcessOnlyStaticFields(classList = {ServletSources.class, ServletSinks.class})
public class ReflexiveXSSSpec implements FluentTQLUserInterface {
    /**
     * encodeForHTML is a OWASP sanitizer that encodes the HTML related data. Therefore, flow should go through this method to avoid vulnerability.
     */
    @InFlowParam(parameterID = {0})
    @OutFlowReturnValue
    public Method sanitizer = new MethodSelector("org.owasp.esapi.Encoder: java.lang.String encodeForHTML(java.lang.String)");

    /**
     * decodeForHTML is a OWASP de-sanitizer that decodes the HTML related data back to HTML entities. Therefore, flow should not go though this method to avoid
     * vulnerability.
     */
    @InFlowParam(parameterID = {0})
    @OutFlowReturnValue
    public Method deSanitizer = new MethodSelector("org.owasp.esapi.Encoder: java.lang.String decodeForHTML(java.lang.String)");

    /**
     * Returns the Internal FluentTQL specification
     *
     * @return Internal FluentTQL specification
     */
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("ReflexiveXSS")
                .from(ServletSources.servletSources)
                .through(deSanitizer)
                .notThrough(sanitizer)
                .to(ServletSinks.servletSinks)
                .report("Reflexive XSS - CWE79 !")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(myTF);

        return myFluentTQLSpecs;
    }
}
