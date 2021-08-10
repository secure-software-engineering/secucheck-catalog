package secucheck.todolistSpecifications;

import secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import secucheck.InternalFluentTQL.dsl.MethodConfigurator;
import secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

/**
 * CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
 * <p>
 * The software does not neutralize or incorrectly neutralizes user-controllable input before
 * it is placed in output that is used as a web page that is served to other users.
 */
@FluentTQLSpecificationClass
public class CWE79_CrossSiteScripting implements FluentTQLUserInterface {

    /**
     * Source
     */
    public Method sourceMethod = new MethodConfigurator(
            "secucheck.todolist.controllers.LoginController: " +
                    "org.springframework.web.servlet.ModelAndView createNewUser(" +
                    "secucheck.todolist.model.User," +
                    "org.springframework.validation.BindingResult," +
                    "javax.servlet.http.HttpServletRequest," +
                    "javax.servlet.http.HttpServletResponse)")
            .out().param(0)
            .configure();


    /**
     * sanitize method is OWASP HTML sanitizer, that sanitizes the special characters, so that SQL Injection does not occur. It is a simple example, For security its better to use
     * encodeForSQL or make the settings of sanitize method to avoid SQL Injection.
     */
    public Method sanitizerMethod = new MethodConfigurator(
            "secucheck.todolist.controllers.LoginController: " +
                    "secucheck.todolist.model.User NameIt(" +
                    "secucheck.todolist.model.User)")
            .in().param(0)
            .out().returnValue()
            .configure();


    /**
     * Sink
     */
    public Method sinkMethod = new MethodConfigurator(
            "secucheck.todolist.service.UserService: " +
                    "void saveUserDefault(" +
                    "secucheck.todolist.model.User)")
            .in().param(0)
            .configure();

    /**
     * Returns the Internal FluentTQL specification
     *
     * @return Internal FluentTQL specifications
     */
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("CWE79_CrossSiteScripting")
                .from(sourceMethod)
                .to(sinkMethod)
                .report("CWE-79 detected: Cross-site Scripting from untrusted value 'String pattern'")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(myTF);

        return myFluentTQLSpecs;
    }
}