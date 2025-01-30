package de.fraunhofer.iem.secucheck.InternalFluentTQL.catalogSpecifications.FuentTQLRepositories.Sources;

import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodSelector;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodSet;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.FluentTQLRepositoryClass;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.OutFlowReturnValue;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;

/**
 * Multiple Source definition for Servlet application
 *
 * @author Ranjith Krishnamurthy
 * @author Goran
 */
@FluentTQLRepositoryClass
public class ServletSources {
    //Below are methods for Servlet application that reads input from the user.

    @OutFlowReturnValue
    public static Method source1 = new MethodSelector(
            "javax.servlet.http.HttpServletRequest: java.lang.String getParameter(java.lang.String)",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source2 = new MethodSelector(
            "javax.servlet.http.HttpServletRequest: java.util.Map getParameterMap()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source3 = new MethodSelector(
            "javax.servlet.http.HttpServletRequest: java.lang.String[] getParameterValues(java.lang.String)",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source4 = new MethodSelector(
            "javax.servlet.http.HttpServletRequest: java.util.Enumeration getParameterNames()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source5 = new MethodSelector(
            "javax.servlet.http.HttpServletRequest: java.lang.String getRequestedSessionId()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source6 = new MethodSelector(
            "javax.servlet.http.HttpServletRequest: java.lang.String getQueryString()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source7 = new MethodSelector(
            "javax.servlet.http.HttpServletRequest: java.lang.String getRemoteUser()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source8 = new MethodSelector(
            "javax.servlet.http.HttpServletRequest: javax.servlet.http.Cookie[] getCookies()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source9 = new MethodSelector(
            "javax.servlet.ServletRequestWrapper: java.lang.String getParameter(java.lang.String)",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source10 = new MethodSelector(
            "javax.servlet.http.HttpServletRequest: javax.servlet.ServletInputStream getInputStream()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source11 = new MethodSelector(
            "javax.servlet.ServletRequestWrapper: javax.servlet.ServletInputStream getInputStream()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source12 = new MethodSelector(
            "javax.servlet.http.HttpSession: java.lang.String getId()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    //Below are methods for header manipulation in Servlet application.
    @OutFlowReturnValue
    public static Method source13 = new MethodSelector(
            "javax.servlet.ServletRequest: java.lang.String getScheme()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source14 = new MethodSelector(
            "javax.servlet.ServletRequest: java.lang.String getProtocol()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source15 = new MethodSelector(
            "javax.servlet.ServletRequest: java.lang.String getContentType()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source16 = new MethodSelector(
            "javax.servlet.ServletRequest: java.lang.String getServerName()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source17 = new MethodSelector(
            "javax.servlet.ServletRequest: java.lang.String getRemoteAddr()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source18 = new MethodSelector(
            "javax.servlet.ServletRequest: java.lang.String getRemoteHost()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source19 = new MethodSelector(
            "javax.servlet.ServletRequest: java.lang.String getRealPath()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source20 = new MethodSelector(
            "javax.servlet.ServletRequest: java.lang.String getLocalName()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source21 = new MethodSelector(
            "javax.servlet.ServletRequest: java.lang.String getLocalAddr()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source22 = new MethodSelector(
            "javax.servlet.ServletRequest: java.lang.String getAuthType()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source23 = new MethodSelector(
            "javax.servlet.ServletRequest: javax.servlet.RequestDispatcher getRequestDispatcher(java.lang.String)",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source24 = new MethodSelector(
            "javax.servlet.http.HttpServletRequest: java.lang.String getQueryString()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source25 = new MethodSelector(
            "javax.servlet.http.HttpServletRequest: java.lang.String getRemoteUser()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source26 = new MethodSelector(
            "javax.servlet.http.HttpServletRequest: int getContentLength()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source27 = new MethodSelector(
            "javax.servlet.http.HttpServletRequest: java.lang.String getContentType()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    @OutFlowReturnValue
    public static Method source28 = new MethodSelector(
            "javax.servlet.http.HttpServletRequest: java.lang.String getMethod()",
            "CWE-20", "CWE-116", "CWE-838", "CWE-138"
    );

    /**
     * This MethodSet contains some of the source methods in Servlet application.
     */
    public static MethodSet servletSources = new MethodSet("servletSources")
            .addMethod(source1)
            .addMethod(source2)
            .addMethod(source3)
            .addMethod(source4)
            .addMethod(source5)
            .addMethod(source6)
            .addMethod(source7)
            .addMethod(source8)
            .addMethod(source9)
            .addMethod(source10)
            .addMethod(source11)
            .addMethod(source12)
            .addMethod(source13)
            .addMethod(source14)
            .addMethod(source15)
            .addMethod(source16)
            .addMethod(source17)
            .addMethod(source18)
            .addMethod(source19)
            .addMethod(source20)
            .addMethod(source21)
            .addMethod(source22)
            .addMethod(source23)
            .addMethod(source24)
            .addMethod(source25)
            .addMethod(source26)
            .addMethod(source27)
            .addMethod(source28);
}
