package nullpointer;

import java.util.ArrayList;
import java.util.List;

import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.CONSTANTS.VARIABLE;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

@FluentTQLSpecificationClass
public class SpecExample1 implements FluentTQLUserInterface {

	/**
     * Sink
     */
	String sinkMethodSign = "nullpointer.example1.Main: "
							+ "void "
							+ "sink"
							+ "(java.lang.String)";
    public Method sinkMethod = new MethodConfigurator(sinkMethodSign)
            					.in().param(0)
            					.configure();
	
	@Override
	public List<FluentTQLSpecification> getFluentTQLSpecification() {
		TaintFlowQuery myTF = new TaintFlowQueryBuilder("Nullpointer_Example1")
                .from(VARIABLE.NULL)
                .to(sinkMethod)
                .report("NULL Pointer Dereference vulnerability!")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(myTF);

        return myFluentTQLSpecs;
	}

}
