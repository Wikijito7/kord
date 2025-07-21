package dev.kord.voice.dave

import java.math.BigInteger

/**
 * Implements displayable codes for the DAVE protocol as specified in the protocol whitepaper.
 * 
 * The epoch authenticator and pairwise key verification fingerprints are displayed using
 * a more flexible variation of Signal's displayable code algorithm.
 */
public object DisplayableCodes {
    
    /**
     * Generates a displayable code from the given byte array.
     * 
     * @param data The input byte array
     * @param desiredCodeLength The desired total length of the displayable code
     * @param groupSize The size of each group in the code
     * @return The displayable code as a string with groups separated by spaces
     */
    public fun generateDisplayableCode(data: ByteArray, desiredCodeLength: Int, groupSize: Int): String {
        require(data.size >= desiredCodeLength) { 
            "Input data length (${data.size}) must be equal to or greater than desired code length ($desiredCodeLength)" 
        }
        require(desiredCodeLength % groupSize == 0) { 
            "Desired code length ($desiredCodeLength) must be a multiple of group size ($groupSize)" 
        }
        require(groupSize < 8) { 
            "Group size ($groupSize) must be smaller than 8" 
        }
        
        val numberOfGroups = desiredCodeLength / groupSize
        val groups = mutableListOf<String>()
        
        for (i in 0 until numberOfGroups) {
            val startIndex = i * groupSize
            val groupBytes = data.sliceArray(startIndex until startIndex + groupSize)
            
            // Create an unsigned integer from the group bytes (MSB to LSB)
            var value = BigInteger.ZERO
            for (byte in groupBytes) {
                value = value.shiftLeft(8).add(BigInteger.valueOf((byte.toInt() and 0xFF).toLong()))
            }
            
            // Modulo by 10^groupSize and pad with leading zeros
            val modulus = BigInteger.TEN.pow(groupSize)
            val groupValue = value.mod(modulus)
            val groupString = groupValue.toString().padStart(groupSize, '0')
            
            groups.add(groupString)
        }
        
        return groups.joinToString(" ")
    }
    
    /**
     * Generates an epoch authenticator displayable code.
     * 
     * The epoch authenticator is a 32-byte input value, an exported secret from the MLS group.
     * We generate a 30 digit displayable code with 6 groups of 5 digits.
     * 
     * @param epochAuthenticator The 32-byte epoch authenticator
     * @return The displayable code as a string
     */
    public fun generateEpochAuthenticatorCode(epochAuthenticator: ByteArray): String {
        require(epochAuthenticator.size >= 32) { 
            "Epoch authenticator must be at least 32 bytes" 
        }
        return generateDisplayableCode(epochAuthenticator, 30, 5)
    }
    
    /**
     * Generates a pairwise verification fingerprint displayable code.
     * 
     * Pairwise verification fingerprints are 64-byte input values.
     * We generate a 45 digit displayable code with 9 groups of 5 digits.
     * 
     * @param fingerprint The 64-byte verification fingerprint
     * @return The displayable code as a string
     */
    public fun generatePairwiseVerificationCode(fingerprint: ByteArray): String {
        require(fingerprint.size >= 64) { 
            "Pairwise verification fingerprint must be at least 64 bytes" 
        }
        return generateDisplayableCode(fingerprint, 45, 5)
    }
    
    /**
     * Parses a displayable code back into its component groups.
     * 
     * @param displayableCode The displayable code string (groups separated by spaces)
     * @return List of group strings
     */
    public fun parseDisplayableCode(displayableCode: String): List<String> {
        return displayableCode.split(" ").filter { it.isNotBlank() }
    }
    
    /**
     * Validates that a displayable code has the correct format.
     * 
     * @param displayableCode The displayable code to validate
     * @param expectedGroupCount The expected number of groups
     * @param expectedGroupSize The expected size of each group
     * @return true if the code is valid, false otherwise
     */
    public fun validateDisplayableCode(
        displayableCode: String,
        expectedGroupCount: Int,
        expectedGroupSize: Int
    ): Boolean {
        val groups = parseDisplayableCode(displayableCode)
        
        if (groups.size != expectedGroupCount) {
            return false
        }
        
        return groups.all { group ->
            group.length == expectedGroupSize && group.all { it.isDigit() }
        }
    }
    
    /**
     * Validates an epoch authenticator displayable code.
     */
    public fun validateEpochAuthenticatorCode(displayableCode: String): Boolean {
        return validateDisplayableCode(displayableCode, 6, 5)
    }
    
    /**
     * Validates a pairwise verification displayable code.
     */
    public fun validatePairwiseVerificationCode(displayableCode: String): Boolean {
        return validateDisplayableCode(displayableCode, 9, 5)
    }
}
