package me.mthw.forge.cracker;

import me.mthw.forge.utils.Utils;

import java.io.File;
import java.io.IOException;

import java.math.BigInteger;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;

import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.TskCoreException;

/**
 * The `BruteCrackerPDF` class is a specialized implementation of the `BruteCracker` class designed to handle password cracking and decryption for PDF files. It supports
 * various PDF encryption revisions and implements algorithms as specified in the PDF standard (ISO 32000-2:2020).
 *
 * This class provides functionality to: - Verify user and owner passwords for PDF documents using different encryption revisions. - Decrypt PDF files using a valid
 * password and save the decrypted file. - Support specific PDF encryption revisions, including revisions 2 through 4 and revision 6.
 *
 * The class uses cryptographic operations such as MD5, SHA-256, AES, and RC4 to implement password verification and decryption algorithms. It adheres to the PDF
 * specification for handling encryption and security settings.
 *
 * Key features include: - Verification of user and owner passwords for different PDF encryption revisions. - Decryption of PDF files by removing encryption and saving
 * the decrypted document. - Support for both standard and advanced encryption algorithms as defined in the PDF specification.
 *
 * Limitations: - Only supports specific PDF encryption revisions (2 through 4, and 6). - Does not support custom or non-standard encryption filters. ZIP Specification
 * checks the password against one or two bytes. Use of library to try extract the file helps, but still can have collisions and return wrong password.
 *
 *
 * References: - ISO 32000-2:2020 - Document management — Portable document format — Part 2: PDF 2.0
 *
 * @see BruteCracker
 * @see AbstractFile
 * @see BlackboardArtifact
 * @see Blackboard
 * @see TskCoreException
 * @see GeneralSecurityException
 */
public class BruteCrackerPDF extends BruteCracker
{

    /**
     * 
     * Contstructor extracts the necessary attributes from the artifact and checks if the file is supported.
     *
     * @param file The file to be processed.
     * @param artifact The blackboard artifact associated with the file.
     * @param blackboard The blackboard instance used to retrieve attribute types.
     * @param passwordList A list of potential passwords to try.
     * @param cancelled An atomic boolean to signal if the operation should be cancelled.
     * @param foundPassword An atomic reference to store the found password, if any.
     * @param control The CrackerControl instance to manage the cracking process.
     * @throws TskCoreException If there is an error accessing the blackboard or artifact attributes.
     * @throws IllegalArgumentException If the PDF filter is unsupported.
     */
    public BruteCrackerPDF(AbstractFile file, BlackboardArtifact artifact, Blackboard blackboard, AtomicBoolean cancelled, AtomicReference<String> foundPassword, CrackerControl control) throws TskCoreException
    {
        super(file, cancelled, foundPassword, control);
        // Check if standard security handler
        String filter = artifact.getAttribute(blackboard.getAttributeType("FORGE_PDF_FILTER")).getValueString();
        if (filter == null || filter.equals("Standard") == false)
            throw new IllegalArgumentException("Unsupported filter: " + filter);

        // Get attributes from the artifact of the file
        R = artifact.getAttribute(blackboard.getAttributeType("FORGE_PDF_REVISION")).getValueInt();
        length = artifact.getAttribute(blackboard.getAttributeType("FORGE_PDF_LENGTH")).getValueInt();
        U = Utils.hexStringToByteArray(artifact.getAttribute(blackboard.getAttributeType("FORGE_PDF_USER_KEY")).getValueString());
        O = Utils.hexStringToByteArray(artifact.getAttribute(blackboard.getAttributeType("FORGE_PDF_OWNER_KEY")).getValueString());
        isMetadataEncrypted = artifact.getAttribute(blackboard.getAttributeType("FORGE_PDF_IS_METADATAENCRYPTED")).getValueInt() == 1;
        P = Utils.binaryStringToByteArray(artifact.getAttribute(blackboard.getAttributeType("FORGE_PDF_PERMISSIONS")).getValueString());
        ID = Utils.hexStringToByteArray(artifact.getAttribute(blackboard.getAttributeType("FORGE_PDF_ID")).getValueString());
    }

    private final int R;
    private final int length;
    private final byte[] U;
    private final byte[] O;
    private final byte[] P;
    private final byte[] ID;

    private final boolean isMetadataEncrypted;
    private final byte[] pad = new byte[] { (byte) 0x28, (byte) 0xBF, (byte) 0x4E, (byte) 0x5E, (byte) 0x4E, (byte) 0x75, (byte) 0x8A, (byte) 0x41, (byte) 0x64, (byte) 0x00, (byte) 0x4E, (byte) 0x56, (byte) 0xFF, (byte) 0xFA, (byte) 0x01, (byte) 0x08, (byte) 0x2E, (byte) 0x2E, (byte) 0x00, (byte) 0xB6, (byte) 0xD0, (byte) 0x68, (byte) 0x3E, (byte) 0x80, (byte) 0x2F, (byte) 0x0C, (byte) 0xA9, (byte) 0xFE, (byte) 0x64, (byte) 0x53, (byte) 0x69, (byte) 0x7A };

    // All referces to the PDF standard are from ISO32000-2:2020
    /**
     * Verifies the provided password against the PDF's encryption settings.
     * 
     * This method supports only specific PDF encryption revisions as defined in Table 21: revisions 2 through 4, and revision 6. For unsupported revisions, the method will
     * return false.
     * 
     * For revisions 2 through 4, the password is verified using either the user password or the owner password verification methods for revision 4. For revision 6, the
     * password is verified using the corresponding user or owner password verification methods for revision 6.
     * 
     * 
     * Note: Method supports ascii password only at this time.
     * 
     * @param password The password to verify.
     * @return {@code true} if the password is valid for the PDF's encryption settings; {@code false} otherwise.
     * @throws GeneralSecurityException If an error occurs during the password verification process in cryptographic operations.
     * @throws IllegalArgumentException If the PDF revision is unsupported.
     */
    @Override
    protected boolean verifyPassword(String password) throws GeneralSecurityException, IllegalArgumentException
    {
        // Supports only versions in Table 21
        if (R <= 4 && R >= 2)
            return verifyUserPasswordRevision4(password) || verifyOwnerPasswordRevision4(password);
        else if (R == 6)
            return verifyUserPasswordRevision6(password) || verifyOwnerPasswordRevision6(password);
        else
            throw new IllegalArgumentException("Unsupported PDF revision: " + R);
    }

    /**
     * Decrypts a PDF file using the provided password and saves the decrypted file.
     *
     * @param password The password used to decrypt the PDF file.
     * @throws TskCoreException If an error occurs while adding the decrypted file to the case.
     * @throws IOException If an I/O error occurs during file operations.
     */
    @Override
    public void decryptFile(String password) throws TskCoreException, IOException, NoCurrentCaseException
    {
        // Read the document
        File inputFile = new File(file.getLocalAbsPath());
        PDDocument document = Loader.loadPDF(inputFile, password);

        // Remove the encryption
        document.setAllSecurityToBeRemoved(true);

        // Save the decrypted document
        File outputFile = new File(getDecryptFilePath());
        outputFile.getParentFile().mkdirs();

        document.save(outputFile);
        document.close();

        // Add the decrypted file to the case
        addDerivedFile(outputFile);
    }

    /**
     * Retrieves the name of the cracker.
     *
     * @return A string representing the name of the cracker.
     */
    @Override
    public String getName()
    {
        return "PDF Cracker";
    }

    /**
     * Verifies the owner password for a PDF document using the algorithm specified in section 7.6.4.4.2 of the PDF specification (Algorithm 3, steps a-d) and section
     * 7.6.4.4.6 (Algorithm 7, step b).
     *
     * This method supports both Revision 2 and Revision 3+ of the PDF encryption standard. It prepares the password, computes the encryption key, and decrypts the owner
     * password to verify its validity.
     *
     * @param passwordString The owner password as a string.
     * @return {@code true} if the owner password is valid; {@code false} otherwise.
     * @throws GeneralSecurityException If an error occurs during cryptographic operations.
     */
    private boolean verifyOwnerPasswordRevision4(String passwordString) throws GeneralSecurityException
    {
        // a
        // Algorithm 3 (7.6.4.4.2) (a-d)
        // a
        byte[] password = preparePassword4(passwordString);
        // b
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        byte[] digest = messageDigest.digest(password);

        // c
        // Revision 3+
        if (R >= 3)
        {
            messageDigest.reset();
            for (int i = 0; i < 50; i++)
            {
                digest = messageDigest.digest(digest);
                messageDigest.reset();
            }
        }

        // d
        // Length of the key is 5 bytes for R2 and length bytes for R3+
        int n = 5;
        if (R >= 3)
            n = length / 8; // bits to bytes

        // Create the key of length n
        byte[] fileEncryptionKey = new byte[n];
        System.arraycopy(digest, 0, fileEncryptionKey, 0, n);

        // Algorithm 7 (7.6.4.4.6)
        // b

        byte[] userPassword;
        Cipher rc4Cipher = Cipher.getInstance("ARCFOUR");

        // Revision 2
        if (R == 2)
        {
            rc4Cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(fileEncryptionKey, "ARCFOUR"));
            userPassword = rc4Cipher.doFinal(O);
        }
        // Revision 3+
        else
        {
            userPassword = O;
            byte[] roundKey = new byte[length / 8];
            for (int i = 19; i >= 0; i--)
            {
                for (int j = 0; j < fileEncryptionKey.length; j++)
                    roundKey[j] = (byte) (fileEncryptionKey[j] ^ i);

                rc4Cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(roundKey, "ARCFOUR"));
                userPassword = rc4Cipher.doFinal(userPassword);
            }
        }
        // c
        return verifyUserPasswordRevision4(userPassword);
    }

    /**
     * Verifies the user password for a PDF document using Revision 4 security.
     *
     * This method prepares the given password string by converting it into a byte array suitable for Revision 4 security and then verifies it against the PDF's security
     * settings.
     *
     * @param passwordString The user password as a string.
     * @return {@code true} if the password is valid for the PDF document; {@code false} otherwise.
     * @throws GeneralSecurityException If an error occurs during cryptographic operations.
     */
    private boolean verifyUserPasswordRevision4(String passwordString) throws GeneralSecurityException
    {
        byte[] password = preparePassword4(passwordString);
        return verifyUserPasswordRevision4(password);
    }

    /**
     * Verifies the user password for a PDF document using the algorithm specified for security handler revision 4 or higher.
     *
     * This method implements the password verification process as described in the PDF specification (ISO 32000-1:2008), specifically sections 7.6.4.3.2, 7.6.4.4.3,
     * 7.6.4.4.4, and 7.6.4.4.5. It calculates the file encryption key and compares the computed user password hash with the stored value.
     *
     * @param password The user password as a byte array.
     * @return {@code true} if the password is valid, {@code false} otherwise.
     * @throws GeneralSecurityException If an error occurs during cryptographic operations.
     */
    private boolean verifyUserPasswordRevision4(byte[] password) throws GeneralSecurityException
    {
        // a
        // Algorithm 4 (7.6.4.4.3) or Algorithm 5 (7.6.4.4.4)
        // a
        // Algorithm 2 (7.6.4.3.2)
        // a
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");

        // b
        messageDigest.update(password);

        // c
        messageDigest.update(O);

        // d - already in proper format
        messageDigest.update(P);

        // e - file attribute only has first element
        messageDigest.update(ID);

        // f
        if (R >= 4 && isMetadataEncrypted == false)
            messageDigest.update(new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF });

        // g
        byte[] digest = messageDigest.digest();

        // h
        if (R >= 3)
        {
            messageDigest.reset();
            byte temp[] = new byte[length / 8]; // bits to bytes
            for (int i = 0; i < 50; i++)
            {
                System.arraycopy(digest, 0, temp, 0, length / 8);
                digest = messageDigest.digest(temp);
                messageDigest.reset();
            }
        }
        // i
        // Length of the key is 5 bytes for R2 and length bytes for R3+
        int n = 5;
        if (R >= 3)
            n = length / 8; // bits to bytes
        byte[] fileEncryptionKey = new byte[n];
        System.arraycopy(digest, 0, fileEncryptionKey, 0, n);

        // Algorithm 4 (7.6.4.4.3) or Algorithm 5 (7.6.4.4.4)

        byte[] computedU;

        Cipher rc4Cipher = Cipher.getInstance("ARCFOUR");
        // Algorithm 5 (7.6.4.4.4)
        if (R >= 3)
        {
            // b
            messageDigest.reset();
            messageDigest.update(pad);

            // c
            messageDigest.update(ID);

            // d
            digest = messageDigest.digest();
            rc4Cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(fileEncryptionKey, "ARCFOUR"));
            computedU = rc4Cipher.doFinal(digest);

            // e
            byte[] roundKey = new byte[length / 8];
            for (int i = 1; i <= 19; i++)
            {
                for (int j = 0; j < roundKey.length; j++)
                    roundKey[j] = (byte) (fileEncryptionKey[j] ^ i);
                rc4Cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(roundKey, "ARCFOUR"));
                computedU = rc4Cipher.doFinal(computedU);
            }
            // Padding not neccessary since comparing only first 16 bytes
        }

        // Algorithm 4 (7.6.4.4.3)
        else
        {
            // b
            rc4Cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(fileEncryptionKey, "ARCFOUR"));
            computedU = rc4Cipher.doFinal(pad);
        }

        // Algorithm 6 (7.6.4.4.5)
        // b
        // Compare whole u for R 2 or first 16 bytes for R 3,4
        byte[] compU;
        if (R >= 3)
        {
            compU = new byte[16];
            System.arraycopy(U, 0, compU, 0, 16);
        }
        else
            compU = U;
        return Arrays.equals(compU, computedU);
    }

    /**
     * Prepares a password by ensuring it is exactly 32 bytes long. If the password exceeds 32 characters, it is truncated to 32 characters. If the password is shorter than
     * 32 characters, it is padded with additional bytes. Paddding is static per the PDF standard.
     * 
     * @param password The input password as a string.
     * @return A byte array of length 32 representing the processed password.
     */
    private byte[] preparePassword4(String password)
    {
        if (password.length() > 32)
            password = password.substring(0, 32);
        byte[] passwordBytes = password.getBytes(Charset.forName("US-ASCII"));
        if (passwordBytes.length < 32)
        {
            byte[] temp = new byte[32];
            System.arraycopy(passwordBytes, 0, temp, 0, passwordBytes.length);
            System.arraycopy(pad, 0, temp, passwordBytes.length, 32 - passwordBytes.length);
            passwordBytes = temp;
        }
        return passwordBytes;
    }

    /**
     * Verifies the owner password for a PDF document using the Revision 6 security handler.
     * 
     * This method implements Algorithm 12 (7.6.4.4.11) as specified in the PDF specification. It prepares the password, constructs the input data, derives the encryption key
     * using Algorithm 2.B (7.6.4.3.4), and compares the derived key with the stored owner hash.
     * 
     * @param passwordString The owner password as a string.
     * @return {@code true} if the provided password matches the owner password; {@code false} otherwise.
     * @throws GeneralSecurityException If an error occurs during the cryptographic operations.
     */
    private boolean verifyOwnerPasswordRevision6(String passwordString) throws GeneralSecurityException
    {
        // Algorithm 12 (7.6.4.4.11)
        // a
        byte[] password = preparePassword6(passwordString);

        byte[] input = new byte[8 + password.length + 48];
        System.arraycopy(password, 0, input, 0, password.length);
        System.arraycopy(O, 32, input, password.length, 8);
        System.arraycopy(U, 0, input, password.length + 8, 48);

        // Algorithm 2.B (7.6.4.3.4)
        byte[] K = algorithm2B(input, password, true);

        // Algorithm 12 (7.6.4.4.11)
        // a
        byte[] Ohash = new byte[32];
        System.arraycopy(O, 0, Ohash, 0, 32);

        return Arrays.equals(K, Ohash);
    }

    // Algorithm 11 (7.6.4.4.10)
    /**
     * Verifies the user password for a PDF document using the Revision 6 security handler.
     * 
     * This method implements Algorithm 11 as described in section 7.6.4.4.10 of the PDF specification. It prepares the password, derives a key using Algorithm 2.B (section
     * 7.6.4.3.4), and compares the derived key with the stored hash to validate the password.
     * 
     * @param passwordString The user-supplied password as a string.
     * @return {@code true} if the password is valid and matches the stored hash; {@code false} otherwise.
     * @throws GeneralSecurityException If an error occurs during the cryptographic operations.
     */
    private boolean verifyUserPasswordRevision6(String passwordString) throws GeneralSecurityException
    {
        // Algorithm 11 (7.6.4.4.10)
        // a
        byte[] password = preparePassword6(passwordString);

        byte[] input = new byte[8 + password.length];
        System.arraycopy(password, 0, input, 0, password.length);
        System.arraycopy(U, 32, input, password.length, 8);
        // Algorithm 2.B (7.6.4.3.4)
        byte[] K = algorithm2B(input, password, false);

        // Algorithm 11 (7.6.4.4.10)
        // a
        byte[] Uhash = new byte[32];
        System.arraycopy(U, 0, Uhash, 0, 32);

        return Arrays.equals(K, Uhash);
    }

    // Algorithm 2.B (7.6.4.3.4)
    /**
     * Implements the algorithm2B cryptographic function.
     * 
     * This method performs a series of cryptographic operations using AES encryption and SHA-based hashing to derive a 32-byte result from the given input, password, and
     * owner flag. The process involves iterative rounds of encryption and hashing with conditional checks and modifications.
     * 
     * @param input The input byte array to be processed.
     * @param password The password byte array used in the cryptographic operations.
     * @param owner A boolean flag indicating whether the owner-specific operations should be applied.
     * @return A 32-byte array resulting from the cryptographic operations.
     * @throws GeneralSecurityException If any cryptographic operation fails, such as invalid cipher initialization or unsupported hashing algorithms.
     */
    private byte[] algorithm2B(byte[] input, byte[] password, boolean owner) throws GeneralSecurityException
    {
        // K
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(input);
        byte[] K = digest.digest();

        // a
        byte[] E = new byte[0];
        /*
         * Do first 64 rounds Per point e Then check if last byte of E (unsigned int) is > r - 32) Repeat until last E <= r - 32
         * 
         * Null warning on E is ignored since first 64 rounds are done before checking and E is set during the first round
         */
        for (int r = 0; r < 64 || (E[E.length - 1] & 0xFF) > r - 32; r++)
        {
            int length = password.length + K.length;
            if (owner)
                length += 48;
            byte[] K0 = new byte[length];
            System.arraycopy(password, 0, K0, 0, password.length);
            System.arraycopy(K, 0, K0, password.length, K.length);
            if (owner)
                System.arraycopy(U, 0, K0, password.length + K.length, 48);

            byte[] K1 = new byte[64 * K0.length];
            for (int i = 0; i < 64; i++)
                System.arraycopy(K0, 0, K1, i * K0.length, K0.length);

            // b
            byte[] keyBytes = new byte[16];
            byte[] IVBytes = new byte[16];
            System.arraycopy(K, 0, keyBytes, 0, 16);
            System.arraycopy(K, 16, IVBytes, 0, 16);
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            IvParameterSpec iv = new IvParameterSpec(IVBytes);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            E = cipher.doFinal(K1);

            // c
            byte[] EH = new byte[16];
            System.arraycopy(E, 0, EH, 0, 16);
            BigInteger bigInt = new BigInteger(1, EH);
            int mod = bigInt.mod(BigInteger.valueOf(3)).intValue();

            // d
            switch (mod)
            {
            case 0:
                digest = MessageDigest.getInstance("SHA-256");
                break;
            case 1:
                digest = MessageDigest.getInstance("SHA-384");
                break;
            case 2:
                digest = MessageDigest.getInstance("SHA-512");
                break;
            default:
                throw new IllegalStateException("Unexpected value: " + mod);
            }

            K = digest.digest(E);

        }
        // f
        byte[] res = new byte[32];
        System.arraycopy(K, 0, res, 0, 32);
        return res;
    }

    /**
     * Converts the given password into a byte array using UTF-8 encoding.
     *
     * @param password The password to be converted into a byte array.
     * @return A byte array representation of the password encoded in UTF-8.
     */
    private byte[] preparePassword6(String password)
    {
        return password.getBytes(StandardCharsets.UTF_8);
    }

}