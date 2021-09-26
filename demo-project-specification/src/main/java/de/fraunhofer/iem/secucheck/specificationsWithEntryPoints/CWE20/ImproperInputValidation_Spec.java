package de.fraunhofer.iem.secucheck.specificationsWithEntryPoints.CWE20;

import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodEntryPoint;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.EntryPoint.EntryPoint;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * CWE-20: Improper Input Validation
 * <p>
 * The product receives input or data, but it does not validate or incorrectly
 * validates that the input has the properties that are required to process
 * the data safely and correctly.
 */
@FluentTQLSpecificationClass
public class ImproperInputValidation_Spec implements FluentTQLUserInterface {

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
    public Method sinkMethod = new MethodConfigurator(
            "de.fraunhofer.iem.secucheck.todolist.service.UserService: " +
                    "void saveUserDefault(" +
                    "de.fraunhofer.iem.secucheck.todolist.model.User)")
            .in().param(0)
            .configure();

    /**
     * Entry Point
     */
    String methodEntryPointName = "de.fraunhofer.iem.secucheck.todolist.controllers.LoginController: "
    		+ "org.springframework.web.servlet.ModelAndView "
    		+ "createNewUser "
    		+ "(de.fraunhofer.iem.secucheck.todolist.model.User, "
    		+ "org.springframework.validation.BindingResult, " + 
    		"javax.servlet.http.HttpServletRequest, "
    		+ "javax.servlet.http.HttpServletResponse)";
    public MethodEntryPoint entryPoint = new MethodEntryPoint(methodEntryPointName);
    public List<EntryPoint> entryPoints = Arrays.asList(entryPoint);

    /**
     * Returns the Internal FluentTQL specification
     *
     * @return Internal FluentTQL specifications
     */
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("CWE20_ImproperInputValidation_WithEntryPoints")
                .atOnlyDSLEntryPoints(entryPoints)
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