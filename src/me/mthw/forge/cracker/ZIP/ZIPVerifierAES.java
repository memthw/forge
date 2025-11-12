package me.mthw.forge.cracker.ZIP;

import me.mthw.forge.utils.Utils;

import java.security.GeneralSecurityException;

import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.TskCoreException;

/**
 * The ZIPVerifierAES class extends the ZIPVerifier class to provide functionality for verifying passwords of AES-encrypted ZIP files. It uses the PBKDF2 key derivation
 * algorithm with HMAC-SHA1 to derive encryption keys and validate password verification values.
 *
 * This class is designed to handle AES-encrypted ZIP files based on the WinZIP AES encryption specification and Dr. Gladman's documentation. It supports different AES
 * versions with varying key sizes and ensures secure password verification.
 *
 * Key features of this class include: - Extracting salt and password verification values from the ZIP file's local header. - Deriving encryption keys using PBKDF2 with
 * HMAC-SHA1. - Validating passwords against the stored password verification value.
 *
 *
 * Note: - The password length must not exceed 128 characters. - Ensure the provided ZIP file is AES-encrypted and adheres to the WinZIP AES specification. - AE-X perfoms check only on two bytes. Use of library to try extract the file helps, but still can have collisions.
 *
 * References: - WinZIP AES Encryption Documentation: https://www.winzip.com/en/support/aes-encryption/ - Dr. Gladman's AES Documentation
 *
 * @see ZIPVerifier
 * @see AESVersion
 */
public class ZIPVerifierAES extends ZIPVerifier
{
    private AESVersion aesVersion;
    private byte[] salt;
    private byte[] passwordVerificationValue;
    private SecretKeyFactory skf;

    /**
     * Constructs a ZIPVerifierAES object for verifying AES-encrypted ZIP files. Extracts the salt and password verification value from the ZIP file's local header.
     *
     * @param artifact The BlackboardArtifact associated with the ZIP file.
     * @param blackboard The Blackboard instance used for reporting results.
     * @param rootFile The AbstractFile representing the root file of the ZIP archive.
     * @param aesVersion The AESVersion specifying the encryption key size and version.
     * @throws TskCoreException If there is an error accessing the file system.
     * @throws GeneralSecurityException If there is an error initializing cryptographic components.
     */
    ZIPVerifierAES(BlackboardArtifact artifact, Blackboard blackboard, AbstractFile rootFile, AESVersion aesVersion) throws TskCoreException, GeneralSecurityException
    {
        super(artifact, blackboard, rootFile);
        this.aesVersion = aesVersion;

        int saltLength = aesVersion.keySize / 16;

        byte[] buffer = new byte[2];
        rootFile.read(buffer, localHeaderOffset + 26, 2);
        short fileNameLength = Utils.byteToShort(buffer);
        rootFile.read(buffer, localHeaderOffset + 28, 2);
        short extraFieldLength = Utils.byteToShort(buffer);
        int offset = localHeaderOffset + extraFieldLength + fileNameLength + 30;

        salt = new byte[saltLength];

        rootFile.read(salt, offset, saltLength);

        passwordVerificationValue = new byte[2];
        rootFile.read(passwordVerificationValue, offset + saltLength, 2);
        skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    }

    /**
     * Verifies the provided password against the stored password verification value. Based on WinZIP Documentation https://www.winzip.com/en/support/aes-encryption/ and Dr.
     * Gladman.
     *
     * @param password The password to verify. Must not exceed 128 characters in length.
     * @return {@code true} if the password is valid and matches the verification value; {@code false} otherwise.
     * @throws GeneralSecurityException If an error occurs during the password verification process.
     * @throws IllegalArgumentException If the password length exceeds 128 characters.
     */

    @Override
    public boolean verifyPassword(String password) throws GeneralSecurityException
    {
        if (password.length() > 128)
            throw new IllegalArgumentException("Password length exceeds 128 characters");

        int derivedKeyLengthBytes = (aesVersion.keySize / 8) * 2 + 2;
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1000, derivedKeyLengthBytes * 8);

        byte[] derivedKey = skf.generateSecret(spec).getEncoded();
        byte[] computedPwdVerificationValue = Arrays.copyOfRange(derivedKey, derivedKey.length - 2, derivedKey.length);

        if (Arrays.equals(computedPwdVerificationValue, passwordVerificationValue))
            return verifyPasswordLib(password);

        return false;
    }

}
