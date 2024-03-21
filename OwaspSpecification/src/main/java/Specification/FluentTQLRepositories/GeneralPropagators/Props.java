package Specification.FluentTQLRepositories.GeneralPropagators;

import de.fraunhofer.iem.secucheck.fluenttql.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.annotations.FluentTQLRepositoryClass;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.MethodPackage.Method;

@FluentTQLRepositoryClass
public class Props {
    public static Method prop1_00008 = new MethodConfigurator("java.net.URLDecoder: " +
            "java.lang.String " +
            "decode(java.lang.String,java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public static Method prop2_00008 = new MethodConfigurator("java.sql.Connection: " +
            "java.sql.CallableStatement " +
            "prepareCall(java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public static Method prop1_00018 = new MethodConfigurator("java.util.Enumeration: " +
            "java.lang.Object " +
            "nextElement()")
            .in().thisObject()
            .out().returnValue()
            .configure();

    public static Method prop2_00018 = new MethodConfigurator("java.net.URLDecoder: " +
            "java.lang.String " +
            "decode(java.lang.String,java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public static Method prop1_00024 = new MethodConfigurator("java.sql.Connection: " +
            "java.sql.PreparedStatement " +
            "prepareStatement(java.lang.String,int,int,int)")
            .in().param(0)
            .out().returnValue()
            .configure();

    public static Method prop1_00341 = new MethodConfigurator("java.util.Enumeration: " +
            "java.lang.Object " +
            "nextElement()")
            .in().thisObject()
            .out().returnValue()
            .configure();

    public static Method prop2_00341 = new MethodConfigurator("java.net.URLDecoder: " +
            "java.lang.String " +
            "decode(java.lang.String,java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();
}
