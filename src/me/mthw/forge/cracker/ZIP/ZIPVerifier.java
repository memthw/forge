package me.mthw.forge.cracker.ZIP;

import java.io.File;
import java.io.IOException;

import java.nio.file.Paths;

import java.security.GeneralSecurityException;

import org.apache.commons.io.FileUtils;

import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.TskCoreException;

import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.exception.ZipException;

/**
 * The ZIPVerifier class provides an abstract base for verifying passwords for ZIP files. It includes functionality to verify passwords, clean up temporary files, and
 * retrieve file paths. Subclasses must implement the abstract method `verifyPassword` to define specific password verification logic.
 */
public abstract class ZIPVerifier
{
    protected final String tempPath = Paths.get(System.getProperty("java.io.tmpdir"), "FORGE", "ZIP").toString();
    protected final AbstractFile rootFile;
    protected final String path;
    protected final int localHeaderOffset;

    /**
     * Enum representing the different versions of AES (Advanced Encryption Standard) based on their key sizes. Values are key sizes in bits.
     */
    public enum AESVersion
    {
        AES_128(128), AES_192(192), AES_256(256);

        public final int keySize;

        private AESVersion(int keySize)
        {
            this.keySize = keySize;
        }
    }

    public ZIPVerifier(BlackboardArtifact artifact, Blackboard blackboard, AbstractFile rootFile) throws TskCoreException
    {
        this.rootFile = rootFile;
        this.path = artifact.getAttribute(blackboard.getAttributeType("FORGE_ZIP_FILE_PATH")).getValueString();
        this.localHeaderOffset = artifact.getAttribute(blackboard.getAttributeType("FORGE_ZIP_FILE_RELATIVE_OFFSET_OF_LOCAL_HEADER")).getValueInt();
    }

    /**
     * Verifies the provided password against the ZIP file's encryption.
     *
     * @param password The password to be verified.
     * @return {@code true} if the password is correct; {@code false} otherwise.
     * @throws GeneralSecurityException If a security-related error occurs during verification.
     */
    public abstract boolean verifyPassword(String password) throws GeneralSecurityException;

    /**
     * Verifies the provided password for a ZIP file by attempting to extract a file from it using zip4j library.
     *
     * @param password The password to verify against the ZIP file.
     * @return {@code true} if the password is correct and the file can be extracted successfully; {@code false} if the password is incorrect.
     */
    protected boolean verifyPasswordLib(String password)
    {
        ZipFile zipFile = new ZipFile(rootFile.getLocalAbsPath(), password.toCharArray());
        try
        {
            zipFile.extractFile(path.substring(1), tempPath);
        }
        catch (ZipException e)
        {
            if (e.getType() == ZipException.Type.WRONG_PASSWORD)
                return false;
        }
        catch (Exception e)
        {
        } finally
        {
            try
            {
                zipFile.close();
            }
            catch (Exception e)
            {
            }
        }
        return true;
    }

    /**
     * Cleans up temporary files by deleting the directory specified by the tempPath variable. Utilizes the FileUtils.deleteDirectory method to perform the deletion.
     * 
     */
    public void clean()
    {
        try
        {
            FileUtils.deleteDirectory(new File(tempPath));
        }
        catch (IOException e)
        {
        }
    }

    /**
     * Retrieves the file path associated with this instance.
     *
     * @return the file path as a String.
     */
    public String getFilePath()
    {
        return path;
    }

}
