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
 * CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
 * <p>
 * The software uses external input to construct a pathname that is intended to identify
 * a file or directory that is located underneath a restricted parent directory,
 * but the software does not properly neutralize special elements within the pathname
 * that can cause the pathname to resolve to a location that is outside of the restricted directory.
 */
@FluentTQLSpecificationClass
public class CWE22_PathTraversal implements FluentTQLUserInterface {

    /**
     * Source
     */
    public Method sourceMethod = new MethodConfigurator(
            "secucheck.todolist.controllers.NewTaskController: " +
                    "java.lang.String saveTask(" +
                    "secucheck.todolist.model.Task," +
                    "org.springframework.web.multipart.MultipartFile," +
                    "org.springframework.web.servlet.mvc.support.RedirectAttributes)")
            .out().param(0)
            .configure();

    /**
     * Sanitizer
     */
    public Method sanitizerMethod = new MethodConfigurator(
            "secucheck.todolist.controllers.NewTaskController: " +
                    "java.lang.String correctFileName(" +
                    "java.lang.String)")
            .in().param(0)
            .out().returnValue()
            .configure();

    /**
     * Sink
     */
    public Method sinkMethod = new MethodConfigurator("secucheck.todolist.service.DirectoryStorageService: " +
            "java.lang.String store(" +
            "org.springframework.web.multipart.MultipartFile," +
            "secucheck.todolist.model.Task," +
            "java.lang.String)")
            .in().param(1)
            .configure();

    /**
     * Returns the Internal FluentTQL specification
     *
     * @return Internal FluentTQL specifications
     */
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("CWE22_PathTraversal")
                .from(sourceMethod)
                .notThrough(sanitizerMethod)
                .to(sinkMethod)
                .report("CWE-22 detected: Path Traversal from untrusted value 'Task newTask'")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(myTF);

        return myFluentTQLSpecs;
    }
}
