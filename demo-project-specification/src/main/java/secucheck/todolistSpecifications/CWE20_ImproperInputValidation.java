package secucheck.todolistSpecifications;

import java.util.ArrayList;
import java.util.List;

import secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import secucheck.InternalFluentTQL.dsl.MethodConfigurator;
import secucheck.InternalFluentTQL.dsl.MethodSelector;
import secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import secucheck.InternalFluentTQL.dsl.annotations.InFlowParam;
import secucheck.InternalFluentTQL.dsl.annotations.OutFlowReturnValue;
import secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

/**
 * CWE-20: Improper Input Validation
 * <p>
 * The product receives input or data, but it does not validate or incorrectly
 * validates that the input has the properties that are required to process
 * the data safely and correctly.
 */
@FluentTQLSpecificationClass
public class CWE20_ImproperInputValidation implements FluentTQLUserInterface {

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
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("CWE20_ImproperInputValidation")
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