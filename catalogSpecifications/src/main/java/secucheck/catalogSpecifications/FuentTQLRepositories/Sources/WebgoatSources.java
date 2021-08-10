package secucheck.catalogSpecifications.FuentTQLRepositories.Sources;

import secucheck.InternalFluentTQL.dsl.MethodSelector;
import secucheck.InternalFluentTQL.dsl.MethodSet;
import secucheck.InternalFluentTQL.dsl.annotations.FluentTQLRepositoryClass;
import secucheck.InternalFluentTQL.dsl.annotations.OutFlowReturnValue;
import secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;

/**
 * Multiple Source definition for Webgoat
 *
 */
@FluentTQLRepositoryClass
public class WebgoatSources {
    @OutFlowReturnValue
    public static final Method source1 = new MethodSelector("org.owasp.webgoat.session.ParameterParser: java.lang.String getRawParameter(java.lang.String, java.lang.String)");

    @OutFlowReturnValue
    public static final Method source2 = new MethodSelector("org.owasp.webgoat.session.ParameterParser: java.lang.String getStringParameter(java.lang.String, java.lang.String)");

    @OutFlowReturnValue
    public static final Method source3 = new MethodSelector("org.owasp.webgoat.session.ParameterParser: int getIntParameter(java.lang.String)");

    @OutFlowReturnValue
    public static final Method source4 = new MethodSelector("org.owasp.webgoat.session.ParameterParser: java.lang.String[] getParameterValues(java.lang.String)");

    /**
     * This MethodSet contains some of the source methods in Webgoat.
     */
    public static MethodSet webgoatSources = new MethodSet("webgoatSources")
            .addMethod(source1)
            .addMethod(source2)
            .addMethod(source3)
            .addMethod(source4);
}
