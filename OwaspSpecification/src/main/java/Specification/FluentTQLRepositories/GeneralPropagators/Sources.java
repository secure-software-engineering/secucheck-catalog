package Specification.FluentTQLRepositories.GeneralPropagators;

import de.fraunhofer.iem.secucheck.fluenttql.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.annotations.FluentTQLRepositoryClass;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.MethodPackage.Method;

@FluentTQLRepositoryClass
public class Sources {
    public static Method source_8 = new MethodConfigurator(
            "javax.servlet.http.HttpServletRequest: " +
                    "java.lang.String " +
                    "getHeader(java.lang.String)")
            .out().returnValue()
            .configure();

    public static Method source_18_341 = new MethodConfigurator(
            "javax.servlet.http.HttpServletRequest: " +
                    "java.util.Enumeration " +
                    "getHeaders(java.lang.String)")
            .out().returnValue()
            .configure();

    public static Method source_24_25_26_27 = new MethodConfigurator(
            "javax.servlet.http.HttpServletRequest: " +
                    "java.lang.String " +
                    "getParameter(java.lang.String)")
            .out().returnValue()
            .configure();

    public static Method source_32_33_34 = new MethodConfigurator(
            "javax.servlet.http.HttpServletRequest: " +
                    "java.util.Map " +
                    "getParameterMap()")
            .out().returnValue()
            .configure();

    public static Method source_37_38_39 = new MethodConfigurator(
            "javax.servlet.http.HttpServletRequest: " +
                    "java.util.Enumeration " +
                    "getParameterNames()")
            .out().returnValue()
            .configure();
}
