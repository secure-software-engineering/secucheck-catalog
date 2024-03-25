package Specification.FluentTQLRepositories.GeneralPropagators;

import de.fraunhofer.iem.secucheck.fluenttql.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.annotations.FluentTQLRepositoryClass;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.MethodPackage.Method;

@FluentTQLRepositoryClass
public class Props {
    public static Method prop_8A_18A_341A = new MethodConfigurator("java.net.URLDecoder: " +
            "java.lang.String " +
            "decode(java.lang.String,java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public static Method prop_8B = new MethodConfigurator("java.sql.Connection: " +
            "java.sql.CallableStatement " +
            "prepareCall(java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public static Method prop_18B_341B_37A = new MethodConfigurator("java.util.Enumeration: " +
            "java.lang.Object " +
            "nextElement()")
            .in().thisObject()
            .out().returnValue()
            .configure();

    public static Method prop_24A_37B = new MethodConfigurator("java.sql.Connection: " +
            "java.sql.PreparedStatement " +
            "prepareStatement(java.lang.String,int,int,int)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public static Method prop_32A_33A_34A = new MethodConfigurator("java.util.Map: " +
            "java.lang.Object " +
            "get(java.lang.Object)")
            .in().thisObject()
            .out().returnValue()
            .configure();
}
