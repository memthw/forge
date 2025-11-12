package me.mthw.forge.cracker.ZIP;

import java.io.File;
import java.io.IOException;

import java.nio.file.Paths;

import java.security.GeneralSecurityException;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.DerivedFile;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.TskData.EncodingType;

import me.mthw.forge.cracker.BruteCracker;
import me.mthw.forge.cracker.CrackerControl;
import me.mthw.forge.cracker.ZIP.ZIPVerifier.AESVersion;

import net.lingala.zip4j.ZipFile;

/**
 * The BruteCrackerZIP class is responsible for performing brute-force password cracking on ZIP files. It supports both ZipCrypto and AES encryption methods (AES-128,
 * AES-192, AES-256). The class extends the BruteCracker base class and provides functionality to verify passwords, decrypt files, and clean up resources.
 *
 * Key features of this class include: - Support for multiple encryption methods used in ZIP files. - Verification of passwords against the encryption method. -
 * Decryption of files once the correct password is found. - Resource management to ensure proper cleanup of allocated resources.
 *
 *
 * Exceptions: - {@link IllegalArgumentException} is thrown if an unsupported encryption method is provided. - {@link GeneralSecurityException} is thrown for errors
 * during password verification. - {@link IOException} and {@link TskCoreException} may be thrown during file decryption.
 *
 * 
 * @see BruteCracker
 * @see ZIPVerifierPK
 * @see ZIPVerifierAES
 */
public class BruteCrackerZIP extends BruteCracker
{

    ZIPVerifier verifier;
    boolean ZipCrypto = false;
    AbstractFile rootFile;

    public BruteCrackerZIP(AbstractFile file, AbstractFile rootFile, Blackboard blackboard, BlackboardArtifact artifact, AtomicBoolean cancelled, AtomicReference<String> foundPassword, CrackerControl control) throws IOException, TskCoreException, GeneralSecurityException
    {
        super(file, cancelled, foundPassword, control);
        this.rootFile = rootFile;

        String encMethod = artifact.getAttribute(blackboard.getAttributeType("FORGE_ZIP_FILE_ENCRYPTION_METHOD")).getValueString();
        switch (encMethod)
        {
        case "ZipCrypto":
            verifier = new ZIPVerifierPK(artifact, blackboard, rootFile);
            ZipCrypto = true;
            break;
        case "AES-128":
            verifier = new ZIPVerifierAES(artifact, blackboard, rootFile, AESVersion.AES_128);
            break;
        case "AES-192":
            verifier = new ZIPVerifierAES(artifact, blackboard, rootFile, AESVersion.AES_192);
            break;
        case "AES-256":
            verifier = new ZIPVerifierAES(artifact, blackboard, rootFile, AESVersion.AES_256);
            break;
        default:
            throw new IllegalArgumentException("Unsupported Encryption Method: " + encMethod);
        }
    }

    /**
     * Verifies the provided password against the encryption method used in the ZIP file.
     *
     * @param password The password to be verified.
     * @return {@code true} if the password is correct; {@code false} otherwise.
     * @throws GeneralSecurityException If an error occurs during the verification process.
     */
    @Override
    protected boolean verifyPassword(String password) throws GeneralSecurityException
    {
        return verifier.verifyPassword(password);
    }

    /**
     * Decrypts a file from a ZIP archive using the provided password.
     *
     * @param password The password to decrypt the ZIP file.
     * @throws TskCoreException If an error occurs during the decryption process.
     * @throws NoCurrentCaseException If there is no current case context available.
     *
     * This method uses the provided password to open the ZIP file and extract a specific file. The extracted file is saved to a module directory. If the decryption is
     * successful, the existing derived file is edited for new path to the case context. Any exceptions during the extraction process are caught and logged.
     */
    @Override
    public void decryptFile(String password) throws TskCoreException, NoCurrentCaseException, IOException
    {
        ZipFile zipFile = new ZipFile(rootFile.getLocalAbsPath(), password.toCharArray());
        String name = verifier.getFilePath().substring(1);
        String parentPath = getDecryptFileParentPath();
        zipFile.extractFile(name, parentPath);
        zipFile.close();

        File decryptedFile = new File(getDecryptFilePath());
        addDerivedFile(decryptedFile);
    }

    /**
     * Retrieves the name of the cracker.
     *
     * @return A string representing the name of the cracker, in this case "PDF Cracker".
     */
    @Override
    public String getName()
    {
        return "ZIP Brute Force Cracker";
    }

    /**
     * Cleans up resources used by the BruteCrackerZIP instance. This method ensures that any allocated resources for the zipCryptoVerifier and zipAESVerifier are properly
     * released. It checks if these verifiers are not null before invoking their respective clean methods.
     */
    @Override
    public void clean()
    {
        verifier.clean();
    }

    /**
     * Edits a derived file in the case database after it has been decrypted. Adds correct path for decrypted file.
     *
     * @param decryptedFile The decrypted file to be added as a derived file.
     * @throws TskCoreException If there is an error updating the derived file in the case database.
     * @throws NoCurrentCaseException If there is no current case open.
     */

    @Override
    protected void addDerivedFile(File decryptedFile) throws TskCoreException, NoCurrentCaseException
    {
        FileManager fileManager = Case.getCurrentCaseThrows().getServices().getFileManager();
        String path = Paths.get(Case.getCurrentCase().getModuleOutputDirectoryRelativePath(), "FORGE", getName(), Long.toString(file.getId()), decryptedFile.getName()).toString();
        fileManager.updateDerivedFile((DerivedFile) file, path, file.getSize(), file.getCtime(), file.getCrtime(), file.getAtime(), file.getMtime(), true, null, null, null, null, null, EncodingType.NONE);
    }

    /**
     * Constructs and returns the parent path for the decrypted file. The path is generated by combining the base decrypt path with the unique identifier of the file.
     *
     * @return A string representing the parent path for the decrypted file.
     */
    private String getDecryptFileParentPath()
    {
        return Paths.get(decryptPath, Long.toString(file.getId())).toString();
    }

}
