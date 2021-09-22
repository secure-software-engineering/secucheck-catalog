package de.fraunhofer.iem.secucheck.dataTypeTransformer.topLevel

/**
 * Dummy top level sink method with the Kotlin's type to evaluate the
 * SecuCheck-Kotlin can handle the Kotlin's data type in top level function without user's work around
 *
 * @author Ranjith Krishnamurthy
 */
fun revealSecret(secret: String?, flag: Boolean): Unit {
    if (flag) {
        println("Flag is ON = $secret")
    } else {
        println("Flag is OFF = $secret")
    }
}

/**
 * Dummy top level sanitizer method with the Kotlin's type to evaluate the
 * SecuCheck-Kotlin can handle the Kotlin's data type in top level function without user's work around
 *
 * @author Ranjith Krishnamurthy
 */
fun sanitizeSecret(secret: String): String {
    var encryptedString = ""

    for (ch in secret) {
        encryptedString += (ch + 10).toChar()
    }

    return encryptedString
}