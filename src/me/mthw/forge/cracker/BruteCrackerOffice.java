package me.mthw.forge.cracker;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import java.security.GeneralSecurityException;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.io.FileUtils;

import org.apache.poi.poifs.crypt.Decryptor;
import org.apache.poi.poifs.crypt.EncryptionInfo;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;

import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.ReadContentInputStream;
import org.sleuthkit.datamodel.TskCoreException;

/**
 * The {@code BruteCrackerOffice} class extends the {@code BruteCracker} class and provides functionality for brute-forcing passwords for encrypted Office files. It
 * utilizes a {@code Decryptor} to verify passwords and manage decryption operations.
 *
 * This class is specifically designed to handle Office file decryption and integrates with the Apache POI library for processing encrypted Office documents.
 *
 * This class requires the Apache POI library for handling Office file encryption.
 *
 * @see BruteCracker
 * @see Decryptor
 * @see POIFSFileSystem
 * @see EncryptionInfo
 */
public class BruteCrackerOffice extends BruteCracker
{
    private Decryptor decryptor;

    public BruteCrackerOffice(AbstractFile file, AtomicBoolean cancelled, AtomicReference<String> foundPassword, CrackerControl control) throws IOException
    {
        super(file, cancelled, foundPassword, control);
        this.decryptor = getDecryptor();
    }

    /**
     * Verifies the provided password by delegating to the decryptor's verifyPassword method.
     *
     * @param password the password to be verified
     * @return {@code true} if the password is verified successfully, {@code false} otherwise
     * @throws GeneralSecurityException if an error occurs during the verification process
     */
    @Override
    protected boolean verifyPassword(String password) throws GeneralSecurityException
    {
        return decryptor.verifyPassword(password);
    }

    /**
     * Decrypts a file using the provided password and saves the decrypted content to a specified path.
     *
     * @param password The password used to decrypt the file.
     * @throws GeneralSecurityException If a security-related error occurs during decryption.
     * @throws IOException If an I/O error occurs while reading or writing the file.
     * @throws TskCoreException If an error occurs related to the forensic framework.
     */
    @Override
    public void decryptFile(String password) throws GeneralSecurityException, IOException, TskCoreException, NoCurrentCaseException
    {
        // Get file path
        String filePath = getDecryptFilePath();

        // Set correct password (since this may not be the thread that found the password)
        decryptor.verifyPassword(password);

        // Save the file
        InputStream dataStream = decryptor.getDataStream(new POIFSFileSystem(new ReadContentInputStream(file)));
        File decryptedFile = new File(filePath);
        FileUtils.copyInputStreamToFile(dataStream, decryptedFile);

        // Add the decrypted file to the case
        addDerivedFile(decryptedFile);
    }

    /**
     * Retrieves a Decryptor instance for decrypting encrypted content.
     *
     * @return A Decryptor object used to decrypt the content.
     * @throws IOException If an I/O error occurs while accessing the file system or reading the encryption information.
     */
    private Decryptor getDecryptor() throws IOException
    {
        POIFSFileSystem fs;
        EncryptionInfo encInfo;

        fs = new POIFSFileSystem(new ReadContentInputStream(file));
        encInfo = new EncryptionInfo(fs);
        return encInfo.getDecryptor();
    }

    /**
     * Retrieves the name of the cracker.
     *
     * @return A string representing the name of the cracker.
     */
    @Override
    public String getName()
    {
        return "Office Cracker";
    }

}
