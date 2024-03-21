package Specification.FluentTQLRepositories.GeneralPropagators;

import de.fraunhofer.iem.secucheck.fluenttql.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.fluenttql.dsl.annotations.FluentTQLRepositoryClass;
import de.fraunhofer.iem.secucheck.fluenttql.interfaces.MethodPackage.Method;

@FluentTQLRepositoryClass
public class Sources {
    public static Method source_00008 = new MethodConfigurator(
            "javax.servlet.http.HttpServletRequest: " +
                    "java.lang.String " +
                    "getHeader(java.lang.String)")
            .out().returnValue()
            .configure();

    public static Method source_00018 = new MethodConfigurator(
            "javax.servlet.http.HttpServletRequest: " +
                    "java.util.Enumeration " +
                    "getHeaders(java.lang.String)")
            .out().returnValue()
            .configure();

    public static Method source_00024 = new MethodConfigurator(
            "javax.servlet.http.HttpServletRequest: " +
                    "java.lang.String " +
                    "getParameter(java.lang.String)")
            .out().returnValue()
            .configure();

    public static Method source_00025 = new MethodConfigurator(
            "javax.servlet.http.HttpServletRequest: " +
                    "java.lang.String " +
                    "getParameter(java.lang.String)")
            .out().returnValue()
            .configure();

    public static Method source_00026 = new MethodConfigurator(
            "javax.servlet.http.HttpServletRequest: " +
                    "java.lang.String " +
                    "getParameter(java.lang.String)")
            .out().returnValue()
            .configure();

    public static Method source_00027 = new MethodConfigurator(
            "javax.servlet.http.HttpServletRequest: " +
                    "java.lang.String " +
                    "getParameter(java.lang.String)")
            .out().returnValue()
            .configure();

    public static Method source_00341 = new MethodConfigurator(
            "javax.servlet.http.HttpServletRequest: " +
                    "java.util.Enumeration " +
                    "getHeaders(java.lang.String)")
            .out().returnValue()
            .configure();
}
