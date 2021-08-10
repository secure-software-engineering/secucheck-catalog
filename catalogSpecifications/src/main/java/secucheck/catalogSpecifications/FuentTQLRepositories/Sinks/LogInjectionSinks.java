package secucheck.catalogSpecifications.FuentTQLRepositories.Sinks;

import secucheck.InternalFluentTQL.dsl.MethodSelector;
import secucheck.InternalFluentTQL.dsl.MethodSet;
import secucheck.InternalFluentTQL.dsl.annotations.FluentTQLRepositoryClass;
import secucheck.InternalFluentTQL.dsl.annotations.InFlowParam;
import secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;

/**
 * Multiple Sinks definition for Log-Injection
 *
 */
@FluentTQLRepositoryClass
public class LogInjectionSinks {
    //Below are few of the list of sinks for Log-Injection.
    @InFlowParam(parameterID = {0})
    public static final Method sink1 = new MethodSelector("java.util.logging.Logger: void info(java.lang.String)");

    @InFlowParam(parameterID = {1})
    public static final Method sink2 = new MethodSelector("java.util.logging.Logger: void log(java.util.logging.Level, java.lang.String)");

    @InFlowParam(parameterID = {0, 1})
    public static final Method sink3 = new MethodSelector("java.util.logging.Logger: void entering(java.lang.String, java.lang.String)");

    @InFlowParam(parameterID = {0, 1})
    public static final Method sink4 = new MethodSelector("java.util.logging.Logger: void exiting(java.lang.String, java.lang.String)");

    /**
     * This MethodSet contains some of the sink methods for Log injection.
     */
    public static MethodSet logInjectionSinks = new MethodSet("logInjectionSinks")
            .addMethod(sink1)
            .addMethod(sink2)
            .addMethod(sink3)
            .addMethod(sink4);
}
