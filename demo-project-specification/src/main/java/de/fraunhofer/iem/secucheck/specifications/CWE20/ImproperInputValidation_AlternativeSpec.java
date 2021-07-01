package de.fraunhofer.iem.secucheck.specifications.CWE20;

import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodSignatureConfigurator;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.MethodSignature;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

/**
 * CWE-20: Improper Input Validation
 * <p>
 * The product receives input or data, but it does not validate or incorrectly
 * validates that the input has the properties that are required to process
 * the data safely and correctly.
 */
@FluentTQLSpecificationClass
public class ImproperInputValidation_AlternativeSpec implements FluentTQLUserInterface {

    /**
     * Source
     */
    public Method sourceMethod = new MethodConfigurator(
            "de.fraunhofer.iem.secucheck.todolist.controllers.LoginController: " +
                    "org.springframework.web.servlet.ModelAndView createNewUser(" +
                    "de.fraunhofer.iem.secucheck.todolist.model.User," +
                    "org.springframework.validation.BindingResult," +
                    "javax.servlet.http.HttpServletRequest," +
                    "javax.servlet.http.HttpServletResponse)")
            .out().param(0)
            .configure();

    /**
     * Sink
     */
    public MethodSignature sinkMethodSign = new MethodSignatureConfigurator()
            .atClass("de.fraunhofer.iem.secucheck.todolist.service.UserService")
            .returns("void")
            .named("saveUserDefault")
            .accepts("de.fraunhofer.iem.secucheck.todolist.model.User")
            .configure();
    public Method sinkMethod = new MethodConfigurator(sinkMethodSign)
            .in().param(0)
            .configure();


    /**
     * Returns the Internal FluentTQL specification
     *
     * @return Internal FluentTQL specifications
     */
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("CWE20_ImproperInputValidation_WithMethodSign")
                .from(sourceMethod)
                .to(sinkMethod)
                .report("CWE-20 detected: Improper Input Validation from 'User user'")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(myTF);

        return myFluentTQLSpecs;
    }

}
