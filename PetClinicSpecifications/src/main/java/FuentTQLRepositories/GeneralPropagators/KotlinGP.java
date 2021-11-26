package FuentTQLRepositories.GeneralPropagators;

import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.FluentTQLRepositoryClass;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.GeneralPropagator;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;

@FluentTQLRepositoryClass
public class KotlinGP {
    @GeneralPropagator
    public static Method classLoaderResource = new MethodConfigurator(
            "kotlin.jvm.internal.Intrinsics: java.lang.String stringPlus(java.lang.String,java.lang.Object)")
            .in().param(0).param(1)
            .out().returnValue()
            .configure();
}
