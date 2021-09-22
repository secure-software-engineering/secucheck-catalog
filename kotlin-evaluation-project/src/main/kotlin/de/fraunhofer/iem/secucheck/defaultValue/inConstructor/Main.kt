package de.fraunhofer.iem.secucheck.defaultValue.inConstructor

/**
 * A top level function (dummy source), this can be used to evaluate the SecuCheck-Kotlin can handle top level function
 * feature in Kotlin
 *
 * @author Ranjith Krishnamurthy
 */
fun getPersonAddress(): String = "Street 123"

/**
 * Dummy function where the taintflow is present
 *
 * @author Ranjith Krishnamurthy
 */
fun readAndStoreDataWithTaintFlow() {
    val data = DummySinkClass(
        data2 = getPersonAddress()
    )

    data.printData()
}

/**
 * Dummy function where the taintflow is not present
 *
 * @author Ranjith Krishnamurthy
 */
fun readAndStoreDataWithOutTaintFlow() {
    val data = DummySinkClass(
        data2 = "This is not sensitive data"
    )

    data.printData()
}