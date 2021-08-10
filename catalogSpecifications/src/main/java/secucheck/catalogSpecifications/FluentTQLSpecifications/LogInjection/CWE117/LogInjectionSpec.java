package secucheck.catalogSpecifications.FluentTQLSpecifications.LogInjection.CWE117;

import secucheck.catalogSpecifications.FuentTQLRepositories.Sinks.LogInjectionSinks;
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
 * Internal FluentTQL specification for Log-Injection.
 *
 */
@FluentTQLSpecificationClass
@ImportAndProcessOnlyStaticFields(classList = {ServletSources.class, LogInjectionSinks.class})
public class LogInjectionSpec implements FluentTQLUserInterface {
    /**
     * encodeForURL is a OWASP sanitizer that encodes the URL. This encodes all the new line and carriage return,
     * therefore Log-Injection will be avoided.
     */
    @InFlowParam(parameterID = {0})
    @OutFlowReturnValue
    public Method sanitizer = new MethodSelector("org.owasp.esapi.Encoder: java.lang.String encodeForURL(java.lang.String)");

    /**
     * decodeFromURL is a OWASP de-sanitizer that decodes the URL. This decodes all the new line and carriage return,
     * therefore this method must be avoided before calling Log-Injection sinks.
     */
    @InFlowParam(parameterID = {0})
    @OutFlowReturnValue
    public Method deSanitizer = new MethodSelector("org.owasp.esapi.Encoder: java.lang.String decodeFromURL(java.lang.String)");

    /**
     * Returns the Internal FluentTQL specification
     *
     * @return Internal FluentTQL specification
     */
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery logInjectionSpec1 = new TaintFlowQueryBuilder("LogInjectionWithDeSanitizer")
                .from(ServletSources.servletSources)
                .notThrough(sanitizer)
                .through(deSanitizer)
                .to(LogInjectionSinks.logInjectionSinks)
                .report("Log-Injection CWE-117!")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        TaintFlowQuery logInjectionSpec2 = new TaintFlowQueryBuilder("LogInjectionWithoutDesanitizer")
                .from(ServletSources.servletSources)
                .notThrough(sanitizer)
                .to(LogInjectionSinks.logInjectionSinks)
                .report("Log-Injection CWE-117!")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(logInjectionSpec1);
        myFluentTQLSpecs.add(logInjectionSpec2);

        return myFluentTQLSpecs;
    }
}
