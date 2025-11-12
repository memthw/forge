package me.mthw.forge.cracker;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;

import java.nio.file.Paths;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;

import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.MessageNotifyUtil;
import org.sleuthkit.autopsy.ingest.IngestServices;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.TskData;

import me.mthw.forge.ingest.ForgeIngestFactory;

/**
 * The {@code BruteCracker} class provides an abstract implementation for a brute-force password cracking mechanism. It is designed to iterate through a list of passwords
 * and attempt to verify each one against a target file. The class is intended to be extended by concrete implementations that define specific password verification and
 * decryption logic.
 * 
 * 
 * Usage: Extend this class and implement the {@code verifyPassword}, {@code decryptFile}, and {@code getName} methods to provide specific functionality.
 * 
 * Thread Safety: This class is designed to be thread-safe, with shared state managed using {@link AtomicBoolean} and {@link AtomicReference}.
 * 
 * Logging: Errors and exceptions are logged using the {@link Logger} instance provided by the subclass.
 * 
 * Progress Reporting: Progress is updated periodically during execution, with a default reporting frequency of 50 iterations.
 * 
 * Cancellation: The cracking process can be interrupted or cancelled using the {@code cancelled} flag or thread interruption.
 * 
 * Resource Cleanup: The {@code clean} method is invoked to release resources or perform cleanup operations when the process is interrupted, cancelled, or completed.
 * 
 */
public abstract class BruteCracker implements Runnable
{
    protected AbstractFile file;
    protected List<String> passwordList;

    protected AtomicBoolean cancelled;
    protected AtomicReference<String> foundPassword;
    protected CrackerControl control;

    protected final int REPORT_FREQ = 50;

    protected Logger logger;

    protected final String decryptPath;

    protected boolean randomPassword = false;
    protected BigInteger randomPasswordStartIndex = BigInteger.ZERO;
    protected BigInteger randomPasswordEndIndex = BigInteger.ZERO;
    protected char[] randomPasswordCharSet = null;

    public BruteCracker(AbstractFile file, AtomicBoolean cancelled, AtomicReference<String> foundPassword, CrackerControl control)
    {
        this.file = file;
        this.passwordList = new ArrayList<>();

        this.cancelled = cancelled;
        this.foundPassword = foundPassword;
        this.control = control;

        this.logger = IngestServices.getInstance().getLogger(ForgeIngestFactory.getModuleName());
        this.decryptPath = Paths.get(Case.getCurrentCase().getModuleDirectory(), "FORGE", getName()).toString();

    }

    /**
     * Verifies if the provided password is correct.
     *
     * @param password The password to be verified.
     * @return {@code true} if the password is correct, {@code false} otherwise.
     * @throws GeneralSecurityException If a security (crypto)-related error occurs during verification.
     */
    protected abstract boolean verifyPassword(String password) throws GeneralSecurityException;

    /**
     * Attempts to decrypt a file using the provided password.
     *
     * @param password The password to use for decryption.
     * @throws TskCoreException If an error occurs during the decryption process.
     * @throws IOException If an I/O error occurs while accessing the file.
     */
    public abstract void decryptFile(String password) throws TskCoreException, IOException, GeneralSecurityException, NoCurrentCaseException;

    /**
     * Retrieves the name associated with the implementing class.
     *
     * @return the name as a {@code String}.
     */
    public abstract String getName();

    /**
     * Cleans up resources or performs necessary cleanup operations if neccessary. Default implementation does nothing.
     */
    public void clean()
    {
    };

    /**
     * Sets the list of passwords to be used by the cracker.
     *
     * @param passwordList the list of passwords to set
     */
    public void setPasswordList(List<String> passwordList)
    {
        this.passwordList = passwordList;
    }

    /**
     * Executes the brute force password cracking process. Iterates through a list of passwords and attempts to verify each one. Updates progress periodically and handles
     * thread interruptions or cancellations. If a valid password is found, it sets the result and terminates the process.
     * 
     * Exceptions are caught and logged appropriately, and resources are cleaned up before exiting the method.
     * 
     * Key behaviors: - Updates progress every 50 iterations. - Handles thread interruptions or cancellations gracefully. - Verifies passwords using a cryptographic library.
     * - Logs and notifies errors for cryptographic or argument-related exceptions. - Stops execution for other threads once a valid password is found or an error occurs.
     */
    @Override
    public void run()
    {
        // Try passwordlist first
        int i = 1;
        for (String password : passwordList)
        {
            // Check every 50 passwords (synchronized access to cancelled)
            if ((i % 50) == 0)
            {
                // Check if the thread should interrupted or cancelled
                if (Thread.interrupted() || cancelled.get())
                {
                    clean();
                    break;
                }
                // Update progress
                control.updateProgress(50);
            }

            try
            {
                // Verify the password, if falls try next
                if (verifyPassword(password) == false)
                {
                    i++;
                    continue;
                }

            }
            catch (GeneralSecurityException e)
            {
                MessageNotifyUtil.Notify.error(getName() + ": Cryptographic library exeption", e.getMessage());
                logger.log(Level.WARNING, "Cryptographic library exception", e.getMessage());
                clean();
                return;
            }
            catch (IllegalArgumentException e)
            {
                MessageNotifyUtil.Notify.error(getName() + ": Exception", e.getMessage());
                logger.log(Level.WARNING, "Exception", e.getMessage());
                clean();
                return;
            }
            // If password found, cancell other threads and set the found password
            cancelled.set(true);
            foundPassword.set(password);

            // cleanup if necessary
            clean();
            return;
        }
        // If random password is enabled, try to find the password in the range
        if (randomPassword)
        {
            List<String> triedPasswordList;
            try
            {
                triedPasswordList = control.getTriedPasswordList();
            }
            catch (TskCoreException e)
            {
                triedPasswordList = new ArrayList<>();
            }
            for (BigInteger index = randomPasswordStartIndex; index.compareTo(randomPasswordEndIndex) < 0; index = index.add(BigInteger.ONE))
            {
                // Check every 50 passwords (synchronized access to cancelled)
                if (index.mod(BigInteger.valueOf(50)).equals(BigInteger.ZERO))
                {
                    // Check if the thread should interrupted or cancelled
                    if (Thread.interrupted() || cancelled.get())
                    {
                        clean();
                        break;
                    }
                    // Update progress
                    control.updateProgress(50);
                }

                String password = indexToPassword(index);
                if (triedPasswordList.contains(password))
                    continue;

                try
                {
                    // Verify the password, if falls try next
                    if (verifyPassword(password) == false)
                    {
                        continue;
                    }

                }
                catch (GeneralSecurityException e)
                {
                    MessageNotifyUtil.Notify.error(getName() + ": Cryptographic library exeption", e.getMessage());
                    logger.log(Level.WARNING, "Cryptographic library exception", e.getMessage());
                    clean();
                    return;
                }
                catch (IllegalArgumentException e)
                {
                    MessageNotifyUtil.Notify.error(getName() + ": Exception", e.getMessage());
                    logger.log(Level.WARNING, "Exception", e.getMessage());
                    clean();
                    return;
                }
                // If password found, cancell other threads and set the found password
                cancelled.set(true);
                foundPassword.set(password);

                // cleanup if necessary
                clean();
                return;
            }
        }
    }

    /**
     * Adds a derived file to the case database under the context of the encrypted file.
     *
     * @param decryptedFile The decrypted file to be added as a derived file.
     * @throws TskCoreException If there is an error adding the derived file to the case database.
     *
     * The method constructs a relative path for the derived file based on the current case's module output directory, the "FORGE" folder, the name of the current object, the
     * ID of the encrypted file, and the name of the decrypted file. It then uses this path to add the derived file to the case database, associating it with the encrypted
     * file.
     */
    protected void addDerivedFile(File decryptedFile) throws TskCoreException, NoCurrentCaseException
    {
        // File relative path to database folder
        String path = Paths.get(Case.getCurrentCase().getModuleOutputDirectoryRelativePath(), "FORGE", getName(), Long.toString(file.getId()), decryptedFile.getName()).toString();

        // Add derived file under encrypted file
        Case.getCurrentCase().getSleuthkitCase().addDerivedFile(decryptedFile.getName(), path, decryptedFile.length(), file.getCtime(), file.getCrtime(), file.getAtime(), file.getMtime(), true, file, null, getName(), null, null, TskData.EncodingType.NONE);
    }

    /**
     * Constructs the file path for the current file by combining the module path, the file's unique ID, and the file's name.
     *
     * @return A string representing the full file path.
     */
    protected String getDecryptFilePath()
    {
        return Paths.get(decryptPath, Long.toString(file.getId()), file.getName()).toString();
    }

    /**
     * Enables the generation of random passwords within a specified range and character set.
     *
     * @param startIndex The starting index for the random password generation range.
     * @param endIndex The ending index for the random password generation range.
     * @param charSet The character set to be used for generating the random password.
     */
    public void enableRandomPassword(BigInteger startIndex, BigInteger endIndex, char[] charSet)
    {
        this.randomPasswordStartIndex = startIndex;
        this.randomPasswordEndIndex = endIndex;
        this.randomPasswordCharSet = charSet;
        this.randomPassword = true;
    }

    /**
     * Converts a numeric index into a corresponding password string based on a character set. The method interprets the index as a base-N number, where N is the size of the
     * character set, and maps each digit to a character in the set.
     *
     * @param index The numeric index to convert into a password. Must be a non-negative value.
     * @return The generated password string corresponding to the given index.
     */
    private String indexToPassword(BigInteger index)
    {
        int base = randomPasswordCharSet.length;
        StringBuilder sb = new StringBuilder();

        // Build password in reverse
        BigInteger baseBI = BigInteger.valueOf(base);
        while (index.compareTo(BigInteger.ZERO) >= 0)
        {
            int charIndex = index.mod(baseBI).intValue();
            sb.append(randomPasswordCharSet[charIndex]);
            index = index.divide(baseBI).subtract(BigInteger.ONE);
            if (index.compareTo(BigInteger.ZERO) < 0)
                break;
        }

        // Reverse back to correct order
        String pwd = sb.reverse().toString();

        return pwd;
    }
}