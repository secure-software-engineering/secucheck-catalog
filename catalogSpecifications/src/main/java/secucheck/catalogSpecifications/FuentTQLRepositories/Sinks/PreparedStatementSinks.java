package secucheck.catalogSpecifications.FuentTQLRepositories.Sinks;

import secucheck.InternalFluentTQL.dsl.MethodSelector;
import secucheck.InternalFluentTQL.dsl.MethodSet;
import secucheck.InternalFluentTQL.dsl.annotations.FluentTQLRepositoryClass;
import secucheck.InternalFluentTQL.dsl.annotations.InFlowParam;
import secucheck.InternalFluentTQL.dsl.annotations.InFlowThisObject;
import secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;

/**
 * Multiple Sinks definition for Prepared-Statements
 *
 */
@FluentTQLRepositoryClass
public class PreparedStatementSinks {
    @InFlowThisObject
    public static final Method sink1 = new MethodSelector("java.sql.PreparedStatement: java.sql.ResultSet executeQuery()");

    @InFlowThisObject
    @InFlowParam(parameterID = {0})
    public static final Method sink2 = new MethodSelector("java.sql.PreparedStatement: java.sql.ResultSet executeQuery(java.lang.String)");

    @InFlowThisObject
    public static final Method sink3 = new MethodSelector("java.sql.PreparedStatement: boolean execute()");

    @InFlowThisObject
    @InFlowParam(parameterID = {0})
    public static final Method sink4 = new MethodSelector("java.sql.PreparedStatement: boolean execute(java.lang.String)");

    /**
     * This MethodSet contains some of the sink methods in Prepared Statements.
     */
    public static MethodSet prepSinks = new MethodSet("PrepSinks")
            .addMethod(sink1)
            .addMethod(sink2)
            .addMethod(sink3)
            .addMethod(sink4);
}
