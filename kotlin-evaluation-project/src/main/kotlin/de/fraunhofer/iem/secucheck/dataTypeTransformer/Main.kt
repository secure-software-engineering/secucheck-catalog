package de.fraunhofer.iem.secucheck.dataTypeTransformer

import de.fraunhofer.iem.secucheck.dataTypeTransformer.classLevel.DummySource
import de.fraunhofer.iem.secucheck.dataTypeTransformer.topLevel.revealSecret
import de.fraunhofer.iem.secucheck.dataTypeTransformer.topLevel.sanitizeSecret

/**
 * Dummy function where the taintflow is present
 *
 * @author Ranjith Krishnamurthy
 */
fun entryPointWithTaintFlow(): Unit {
    val dummySource: DummySource = DummySource()

    var secret: String = dummySource.generateSecret(100, "Ranjith", listOf())

    secret = dummySource.propagateEverything(secret)

    revealSecret(secret, true)
}

/**
 * Dummy function where the taintflow is not present
 *
 * @author Ranjith Krishnamurthy
 */
fun entryPointWithOutTaintFlow(): Unit {
    val dummySource: DummySource = DummySource()

    var secret: String = dummySource.generateSecret(100, "Ranjith", listOf())

    secret = dummySource.propagateEverything(secret)

    val encryptedString = sanitizeSecret(secret)

    revealSecret(encryptedString, true)
}