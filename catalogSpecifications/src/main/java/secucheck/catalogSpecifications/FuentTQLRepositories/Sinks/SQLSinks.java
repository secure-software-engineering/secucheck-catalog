package secucheck.catalogSpecifications.FuentTQLRepositories.Sinks;

import secucheck.InternalFluentTQL.dsl.MethodSelector;
import secucheck.InternalFluentTQL.dsl.MethodSet;
import secucheck.InternalFluentTQL.dsl.annotations.FluentTQLRepositoryClass;
import secucheck.InternalFluentTQL.dsl.annotations.InFlowParam;
import secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;

/**
 * Multiple Sinks definition for SQL.
 *
 */
@FluentTQLRepositoryClass
public class SQLSinks {
    //Below are the few sink methods from SQL.
    @InFlowParam(parameterID = {0})
    public static final Method sink1 = new MethodSelector("java.sql.Statement: java.sql.ResultSet executeQuery(java.lang.String)");

    @InFlowParam(parameterID = {0})
    public static final Method sink2 = new MethodSelector("java.sql.Statement: int executeUpdate(java.lang.String)");

    @InFlowParam(parameterID = {0})
    public static final Method sink3 = new MethodSelector("java.sql.Statement: int executeQuery(java.lang.String, int)");

    @InFlowParam(parameterID = {0})
    public static final Method sink4 = new MethodSelector("java.sql.Statement: long executeLargeUpdate(java.lang.String)");

    @InFlowParam(parameterID = {0})
    public static final Method sink5 = new MethodSelector("java.sql.Statement: boolean execute(java.lang.String)");

    /**
     * This MethodSet contains some of the sink methods in SQL statements.
     */
    public static MethodSet sqlSinks = new MethodSet("sqlSinks")
            .addMethod(sink1)
            .addMethod(sink2)
            .addMethod(sink3)
            .addMethod(sink4)
            .addMethod(sink5);
}
