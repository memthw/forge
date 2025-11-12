package me.mthw.forge.cracker;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.logging.Level;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.openide.util.Cancellable;
import org.openide.util.Pair;
import org.openide.util.RequestProcessor;
import org.openide.util.Task;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.casemodule.services.TagsManager;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.MessageNotifyUtil;
import org.sleuthkit.autopsy.ingest.IngestServices;
import org.sleuthkit.autopsy.progress.AppFrameProgressBar;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Host;
import org.sleuthkit.datamodel.HostManager;
import org.sleuthkit.datamodel.AnalysisResult;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.ContentTag;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.DataSource;
import org.sleuthkit.datamodel.TagName;

import me.mthw.forge.CrackerOptions;
import me.mthw.forge.cracker.ZIP.BruteCrackerZIP;
import me.mthw.forge.ingest.ForgeIngestFactory;
import me.mthw.forge.utils.Utils;

/**
 * The CrackerControl class is responsible for managing the brute-force cracking process for various file types.
 */
public class CrackerControl implements Runnable
{

    AbstractFile file;
    AbstractFile rootFile;
    Blackboard blackboard;
    CrackerOptions crackerOptions;

    BlackboardArtifact artifact = null;
    FileManager fileManager = null;

    // Fields to control cracker threads
    private RequestProcessor rp;
    private AtomicBoolean cancelled = new AtomicBoolean(false);
    private AtomicReference<String> foundPassword = new AtomicReference<>(null);
    private int threadsCount;
    private List<BruteCracker> crackers = new ArrayList<>();

    // Fields for progress bar
    private long overallProgress = 0;
    private int passwordCount;
    private final AppFrameProgressBar progress;

    private boolean randomInProgress = false;
    Logger logger;

    /**
     * The CrackerControl class is responsible for managing and orchestrating the brute-force cracking process for various file types. It initializes the necessary cracker
     * implementations based on the file type and handles multi-threaded execution, progress tracking, and cancellation behavior.
     *
     * @param file The file to be processed by the cracker.
     * @param rootFile The root file associated with the current file.
     * @param blackboard The blackboard for storing results and artifacts.
     * @param crackerOptions The options and configurations for the cracking process.
     *
     * The constructor performs the following tasks: - Initializes the thread pool for cracking operations. - Retrieves artifacts associated with the file and determines the
     * appropriate cracker implementation based on the artifact type. - Creates and configures cracker instances for supported file types such as ZIP, PDF, and Office
     * documents. - Handles exceptions that may occur during initialization, such as IllegalArgumentException, IOException, GeneralSecurityException, TskCoreException, or
     * NoCurrentCaseException. - Configures random password generation if enabled in the cracker options. - Sets up a progress bar to track the cracking process and defines
     * cancellation behavior.
     *
     * Supported artifact types: - FORGE_ZIP_FILE: Uses BruteCrackerZIP for ZIP files. - FORGE_PDF: Uses BruteCrackerPDF for PDF files. - FORGE_OFFICE: Uses
     * BruteCrackerOffice for Office documents.
     *
     * Exceptions: - IllegalArgumentException: Thrown if an invalid argument is encountered. - IOException: Thrown if an I/O error occurs. - GeneralSecurityException: Thrown
     * if a security-related error occurs. - TskCoreException: Thrown if an error occurs in the Sleuth Kit core. - NoCurrentCaseException: Thrown if there is no active case.
     */
    public CrackerControl(AbstractFile file, AbstractFile rootFile, Blackboard blackboard, CrackerOptions crackerOptions)
    {
        this.threadsCount = crackerOptions.threadsCount;
        this.file = file;
        this.crackerOptions = crackerOptions;
        this.blackboard = blackboard;
        this.rootFile = rootFile;
        this.logger = IngestServices.getInstance().getLogger(ForgeIngestFactory.getModuleName());

        rp = new RequestProcessor("FORGE Brute Cracker", threadsCount, true);
        List<BlackboardArtifact> artifacts;

        // Prepare cracker implementations based on file
        try
        {
            this.fileManager = Case.getCurrentCaseThrows().getServices().getFileManager();
            artifacts = file.getAllArtifacts();
            forloop: for (BlackboardArtifact art : artifacts)
            {
                String typestr = art.getType().getTypeName();
                switch (typestr)
                {
                case "FORGE_ZIP_FILE":
                    artifact = art;
                    for (int i = 0; i < threadsCount; i++)
                        crackers.add(new BruteCrackerZIP(file, rootFile, blackboard, art, cancelled, foundPassword, this));
                    break forloop;
                case "FORGE_PDF":
                    artifact = art;
                    for (int i = 0; i < threadsCount; i++)
                        crackers.add(new BruteCrackerPDF(file, art, blackboard, cancelled, foundPassword, this));
                    break forloop;
                case "FORGE_OFFICE":
                    artifact = art;
                    for (int i = 0; i < threadsCount; i++)
                        crackers.add(new BruteCrackerOffice(file, cancelled, foundPassword, this));
                    break forloop;
                case "FORGE_ZIP":
                    break forloop;
                default:
                    break;
                }
            }
        }
        catch (IllegalArgumentException | IOException | GeneralSecurityException | TskCoreException | NoCurrentCaseException e)
        {
            MessageNotifyUtil.Notify.error("Forge Cracker factory: Exception", e.getMessage());
            logger.log(Level.WARNING, "Exception", e.getMessage());
        }

        // Generate ranges for each thread to generate all possible passwords with same count for each thread
        if (crackerOptions.randomPassword)
        {
            int i = 0;
            for (Pair<Double, Double> range : getRandomPasswordRanges())
            {
                crackers.get(i).enableRandomPassword(range.first(), range.second(), crackerOptions.randomPasswordCharSet);
                i++;
            }
        }

        // Create progress bar and set cancellation behavior
        progress = new AppFrameProgressBar(crackers.get(0).getName() + " on " + file.getName());
        Cancellable cancellable = () -> {
            progress.setCancelling("Cancelling " + crackers.get(0).getName() + "on file " + file.getName());
            cancelled.set(true);
            return true;
        };

        progress.setCancellationBehavior(cancellable);
    }

    /**
     * Updates the overall progress of the password cracking process by adding the progress made by a single thread. This method is synchronized to ensure thread safety when
     * multiple threads update the progress concurrently.
     *
     * @param threadProgress The progress made by a single thread, represented as the number of passwords attempted by that thread.
     */
    public synchronized void updateProgress(int threadProgress)
    {
      

        overallProgress += threadProgress;
        if (randomInProgress)
        {
            progress.progress("Tried " + overallProgress + " passwords");
            return;
        }
        if (overallProgress > passwordCount)
        {
            progress.switchToIndeterminate("Tried " + overallProgress + " passwords");
            randomInProgress = true;
            return;
        }
        progress.progress("Tried " + overallProgress + " passwords", (int)overallProgress);

    }

    /**
     * Executes the cracking process for a given file using a list of brute force crackers. This method manages the lifecycle of cracking tasks, including starting,
     * monitoring, and handling results or errors. It also updates the progress bar and notifies the user of the outcome.
     *
     * Steps performed by this method:
     * 
     * 
     * Checks if the necessary prerequisites (crackers, resource pool, artifact) are available. Initializes and starts cracking tasks using the provided crackers. Waits for
     * all cracking tasks to complete. Handles the results:
     * 
     * If no password is found and the process is not cancelled, notifies the user. If the process is cancelled and no password is found, notifies the user. If a password is
     * found, notifies the user, adds the password to the artifact, and optionally decrypts the file if auto-decrypt is enabled.
     * 
     *
     * Exceptions during decryption are caught and reported to the user.
     * 
     *
     * Note: This method assumes that the crackers and related resources are properly initialized before invocation.
     * 
     */
    @Override
    public void run()
    {

        if (crackers.size() == 0 || rp == null || artifact == null)
            return;

        progress.start("Generating passwod list");
        List<List<String>> passwordLists;

        try
        {
            passwordLists = getPasswordLists(threadsCount, artifact);
        }
        catch (TskCoreException | NoCurrentCaseException e)
        {
            MessageNotifyUtil.Notify.error("Error getting password list", e.getMessage());
            logger.log(Level.WARNING, "Error getting password list", e.getMessage());
            progress.finish();
            return;
        }

        if (passwordLists.size() != threadsCount && crackerOptions.randomPassword == false)
        {
            MessageNotifyUtil.Notify.error("Error getting password list", "Password list size does not match number of threads");
            logger.log(Level.WARNING, "Error getting password list", "Password list size does not match number of threads");
            progress.finish();
            return;
        }

        int i = 0;
        for (BruteCracker cracker : crackers)
        {
            cracker.setPasswordList(passwordLists.get(i));
            i++;
        }

        // Set the progress bar to the number of passwords
        progress.switchToDeterminate(crackers.get(0).getName() + " started on file " + file.getName(), 0, passwordCount);

        // List of running tasks
        List<Task> tasks = new ArrayList<>();

        // Create and start cracker threads
        for (BruteCracker cracker : crackers)
        {
            tasks.add(rp.post(cracker));
        }

        // Wait for all cracker threads to finish
        for (Task task : tasks)
        {
            task.waitFinished();
        }
        progress.finish();

        // All threads finished and no password found
        if (cancelled.get() == false && foundPassword.get() == null)
        {
            MessageNotifyUtil.Notify.info(crackers.get(0).getName() + " No password found", crackers.get(0).getName() + ": did not find password for file " + file.getName());
            return;
        }

        // Thread finished and no password found
        if (cancelled.get() == true && foundPassword.get() == null)
        {
            MessageNotifyUtil.Notify.info(crackers.get(0).getName() + " cancelled", crackers.get(0).getName() + " on file " + file.getName() + " cancelled");
            return;
        }

        // Thread finished and password found

        // Get the password
        String password = foundPassword.get();
        MessageNotifyUtil.Notify.info(file.getName() + " Password found", crackers.get(0).getName() + ": Password for " + file.getName() + " found: " + password);

        // Add the password to the artifact
        addPasswordAttribute(password, artifact);

        // If autodecrypt is enabled, decrypt the file
        if (crackerOptions.decryptFile)
            try
            {
                crackers.get(0).decryptFile(password);
            }
            catch (TskCoreException | IOException | GeneralSecurityException | NoCurrentCaseException e)
            {
                MessageNotifyUtil.Notify.error(crackers.get(0).getName() + " : Failed to decrypt file " + file.getName(), e.getMessage());
            }
    }

    /**
     * Generates a list of password lists for use in a password cracking process. The method collects passwords from various sources such as common password lists, strings
     * extracted from files, tagged files, and custom files. It also removes passwords that have already been tried and distributes the remaining passwords across multiple
     * lists for parallel processing.
     *
     * @param numberOfLists The number of password lists to generate, typically corresponding to the number of threads or workers.
     * @param removePasswordArtifact The artifact used to track and remove already tried passwords.
     * @return A list of password lists, where each inner list contains a subset of passwords.
     * @throws TskCoreException If an error occurs while interacting with the Sleuth Kit database.
     * @throws NoCurrentCaseException If there is no current case open in the application.
     */
    private List<List<String>> getPasswordLists(int numberOfLists, BlackboardArtifact removePasswordArtifact) throws TskCoreException, NoCurrentCaseException
    {
        HashSet<String> passwordList = new HashSet<>();
        // https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials
        if (crackerOptions.common)
        {
            int count = Integer.parseInt(crackerOptions.commonCount.replaceAll("\\s+", ""));
            InputStream is = getClass().getResourceAsStream("/me/mthw/forge/resources/wordlists/" + count + ".txt");
            if (is != null)
            {
                BufferedReader reader = new BufferedReader(new InputStreamReader(is));
                try
                {
                    while (reader.ready())
                    {
                        passwordList.add(reader.readLine());
                    }
                }
                catch (IOException e)
                {
                    MessageNotifyUtil.Notify.error(": Error reading common password list", e.getMessage());
                    logger.log(Level.WARNING, "Error reading common password list", e.getMessage());
                }

            }
        }

        // Find all strings in files
        if (crackerOptions.strings)
        {
            List<AbstractFile> files = new ArrayList<>();
            String type = crackerOptions.stringsType;
            HostManager manager = Case.getCurrentCaseThrows().getSleuthkitCase().getHostManager();
            switch (type)
            {
            // All files in case
            case "All":
                for (Host host : manager.getAllHosts())
                {
                    for (DataSource source : manager.getDataSourcesForHost(host))
                    {
                        files.addAll(fileManager.findFiles(source, "%"));
                    }
                }
                break;

            // All files in same hostname
            case "Hostname":
                Host host = ((DataSource) file.getDataSource()).getHost();
                for (DataSource source : manager.getDataSourcesForHost(host))
                {
                    files.addAll(fileManager.findFiles(source, "%"));
                }
                break;

            // All files in same data source
            case "Data Source":
                files = fileManager.findFiles(file.getDataSource(), "%");
                break;
            // All files in same folder

            case "Folder":
                // If rootfile set (eg zip), use that as parent
                if (rootFile != null)
                {
                    if (rootFile.getParent() instanceof AbstractFile)
                        files = fileManager.findFiles("%", (AbstractFile) rootFile.getParent());
                    else
                        files = fileManager.findFiles(rootFile.getDataSource(), "%");
                }
                // Use files parent
                else
                {
                    if (file.getParent() instanceof AbstractFile)
                        files = fileManager.findFiles("%", (AbstractFile) file.getParent());
                    else
                        files = fileManager.findFiles(file.getDataSource(), "%");
                }
                break;
            default:
                break;
            }

            // For each file extract strings and add to password list
            for (AbstractFile file : files)
            {
                try
                {
                    passwordList.addAll(Utils.extractStringFromFile(file));
                }
                catch (Exception e)
                {
                    continue;
                }

            }
        }

        // If tag is set, read all files with the tag and add to password list
        if (crackerOptions.tag)
        {
            TagsManager tagsManager = Case.getCurrentCaseThrows().getServices().getTagsManager();
            Map<String, TagName> nameMap = tagsManager.getDisplayNamesToTagNamesMap();
            if (nameMap.containsKey("FORGE Cracker Source"))
            {
                List<ContentTag> contentTags = tagsManager.getContentTagsByTagName(nameMap.get("FORGE Cracker Source"));
                for (ContentTag tag : contentTags)
                {
                    try
                    {
                        passwordList.addAll(Utils.extractStringFromFile((AbstractFile) tag.getContent()));
                    }
                    catch (Exception e)
                    {
                        continue; // Skip files that cannot be read
                    }

                }
            }

        }

        // If custom file is set, read it and add to password list
        if (crackerOptions.file)
        {
            InputStream is = null;
            BufferedReader reader = null;
            try
            {
                if (Files.probeContentType(Paths.get(crackerOptions.filePath)).equals("text/plain") == false)
                {
                    MessageNotifyUtil.Notify.error(": Error reading wordlist file", "File is not a text file");
                    logger.log(Level.WARNING, "Error reading wordlist file", "File is not a text file");
                    return new ArrayList<>();
                }
            }
            catch (IOException e)
            {
                MessageNotifyUtil.Notify.error(": Error reading wordlist file", "File is not a text file");
                logger.log(Level.WARNING, "Error reading wordlist file", "File is not a text file");
                return new ArrayList<>();
            }
            try
            {
                is = new FileInputStream(crackerOptions.filePath);
                reader = new BufferedReader(new InputStreamReader(is));
                while (reader.ready())
                {
                    passwordList.add(reader.readLine());
                }
            }
            catch (IOException e)
            {
                MessageNotifyUtil.Notify.error(": Error reading wordlist file", e.getMessage());
                logger.log(Level.WARNING, "Error reading wordlist file", e.getMessage());
            } finally
            {

                try
                {
                    if (is != null)
                        is.close();
                    if (reader != null)
                        reader.close();
                }
                catch (IOException e)
                {
                }

            }
        }
        // Remove already tried passwords
        removeTriedPasswords(removePasswordArtifact, passwordList);

        // Create list of lists for each thread
        List<List<String>> passwordLists = new ArrayList<>();
        // Save the number of passwords for progress barq
        passwordCount = passwordList.size();

        // Init password list to number of threads
        for (int i = 0; i < numberOfLists; i++)
        {
            passwordLists.add(new ArrayList<>());
        }

        // Distribute passwords to each list
        int index = 0;
        for (String password : passwordList)
        {
            passwordLists.get(index % numberOfLists).add(password);
            index++;
        }
        return passwordLists;
    }

    /**
     * Removes passwords from the provided password list that have already been tried, as indicated by the specified artifact's attribute.
     *
     * @param artifact The BlackboardArtifact containing the attribute with the list of tried passwords. If null, the method returns without performing any operation.
     * @param passwordList A HashSet of passwords to be filtered. Any passwords found in the artifact's attribute will be removed from this list.
     * @throws TskCoreException If there is an error accessing the artifact's attributes.
     */
    private void removeTriedPasswords(BlackboardArtifact artifact, HashSet<String> passwordList) throws TskCoreException
    {

        for (String password : getTriedPasswordList())
            passwordList.remove(password);
    }

    /**
     * Retrieves a list of passwords that have been tried, as stored in the artifact's "FORGE_TRIED_PASSWORD" attribute. If the artifact or the attribute is null, an empty
     * list is returned.
     *
     * @return A list of tried passwords, or an empty list if no passwords are available.
     * @throws TskCoreException If an error occurs while accessing the artifact's attributes.
     */
    public List<String> getTriedPasswordList() throws TskCoreException
    {
        if (artifact == null || artifact.getType().getTypeName().equals("FORGE_ZIP_FILE") == false)
            return new ArrayList<>();

        BlackboardAttribute attribute = artifact.getAttribute(blackboard.getAttributeType("FORGE_TRIED_PASSWORD"));
        if (attribute == null)
            return new ArrayList<>();

        String passwords = attribute.getValueString();
        return Arrays.asList(passwords.split(","));

    }

    /**
     * Adds a password attribute to the specified artifact. If the artifact already contains a password attribute, it is replaced with the new password. For artifacts of type
     * "FORGE_ZIP_FILE", the password is also added to a list of tried passwords to handle potential password collisions.
     *
     * This method ensures that the artifact's attributes are updated correctly by removing the old artifact and creating a new one with the updated attributes, as Autopsy
     * does not allow direct modification of existing attributes.
     *
     * @param password The password to be added as an attribute.
     * @param artifact The artifact to which the password attribute will be added.
     *
     */
    private void addPasswordAttribute(String password, BlackboardArtifact artifact)
    {
        try
        {
            // Get password attribute from artifact
            BlackboardAttribute.Type attributeType = blackboard.getOrAddAttributeType("FORGE_PASSWORD", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Password");
            BlackboardAttribute attribute = artifact.getAttribute(attributeType);
            BlackboardArtifact.Type artifactType = artifact.getType();

            // If attribute exists
            if (attribute != null)
            {
                // Get artifact
                AnalysisResult result = file.getAnalysisResults(artifactType).get(0);

                // Get existing attributes
                List<BlackboardAttribute> attributes = result.getAttributes();

                // Remove existing password attribute
                attributes.removeIf(obj -> obj.getAttributeType().equals(attributeType));

                // If the artifact is a FORGE_ZIP_FILE, add the password to the tried password list, since ZIP can have collisions
                if (artifact.getType().getTypeName().equals("FORGE_ZIP_FILE"))
                {
                    String triedPasswordList;

                    // Get the tried password list
                    int index = getIndex(attributes, "FORGE_TRIED_PASSWORD");

                    // If the tried password list exists, add the new password to it
                    if (index != -1)
                    {
                        triedPasswordList = attributes.get(index).getValueString();
                        if (triedPasswordList == null)
                            triedPasswordList = password;
                        else
                            triedPasswordList += "," + password;
                        attributes.remove(index);
                    }

                    // If the tried password list does not exist, create it
                    else
                        triedPasswordList = password;

                    // Add the tried password list to the attributes
                    attributes.add(new BlackboardAttribute(blackboard.getOrAddAttributeType("FORGE_TRIED_PASSWORD", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Tried Passwords"), ForgeIngestFactory.getModuleName(), triedPasswordList));
                }

                // Delete old artifact since autopsy does not allow updating or removing existing attributes
                blackboard.deleteAnalysisResult(result);

                // Add the artifact again with the new password attribute
                attributes.add(new BlackboardAttribute(attributeType, ForgeIngestFactory.getModuleName(), password));
                BlackboardArtifact newArtifact = file.newAnalysisResult(artifactType, result.getScore(), result.getConclusion(), result.getConfiguration(), result.getJustification(), attributes).getAnalysisResult();
                blackboard.postArtifact(newArtifact, ForgeIngestFactory.getModuleName(), null);
            }
            // If attribute does not exist, create new one
            else
            {
                // If the artifact is a FORGE_ZIP_FILE, add the password to the tried password list, since ZIP can have collisions
                if (artifact.getType().getTypeName().equals("FORGE_ZIP_FILE"))
                    artifact.addAttribute(new BlackboardAttribute(blackboard.getOrAddAttributeType("FORGE_TRIED_PASSWORD", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Tried Passwords"), ForgeIngestFactory.getModuleName(), password));
                artifact.addAttribute(new BlackboardAttribute(attributeType, ForgeIngestFactory.getModuleName(), password));
            }

        }
        catch (TskCoreException | IllegalArgumentException | BlackboardException e)
        {
            MessageNotifyUtil.Notify.error(": Error adding password attribute to file", e.getMessage());
            logger.log(Level.WARNING, "Error adding password attribute to file", e.getMessage());
        }
    }

    /**
     * Retrieves the index of the first occurrence of an attribute in the list that matches the specified attribute type.
     *
     * @param attributes The list of BlackboardAttribute objects to search through.
     * @param attributeType The type name of the attribute to find.
     * @return The index of the matching attribute in the list, or -1 if no match is found.
     */
    private int getIndex(List<BlackboardAttribute> attributes, String attributeType)
    {
        for (int i = 0; i < attributes.size(); i++)
        {
            if (attributes.get(i).getAttributeType().getTypeName().equals(attributeType))
                return i;
        }
        return -1;
    }

    /**
     * Generates a list of ranges representing the distribution of random password generation tasks across multiple threads.
     * 
     * Each range is defined as a pair of doubles, where the first value represents the starting index and the second value represents the ending index of the range. These
     * ranges are calculated based on the total number of possible passwords within the specified length range and the number of threads available for processing.
     * 
     * The method takes into account the character set and the minimum and maximum password lengths defined in the cracker options. It ensures that the ranges are evenly
     * distributed among the threads, with any remainder being included in the last range.
     * 
     * @return A list of pairs, where each pair represents a range of indices for password generation tasks.
     */
    private List<Pair<Double, Double>> getRandomPasswordRanges()
    {
        List<Pair<Double, Double>> ranges = new ArrayList<>();
        double total = 0;
        double skip = 0;

        for (int len = crackerOptions.randomPasswordMinLength; len <= crackerOptions.randomPasswordMaxLength; len++)
            total += Math.pow(crackerOptions.randomPasswordCharSet.length, len);

        for (int len = 0; len < crackerOptions.randomPasswordMinLength; len++)
            skip += Math.pow(crackerOptions.randomPasswordCharSet.length, len);

        skip--;
        double each = Math.ceil((total) / threadsCount);
        for (int i = 0; i < threadsCount; i++)
        {
            double start = skip + (i * each);
            double end = skip + ((i + 1) * each);
            if (end > total + skip)
                end = total + skip;
            ranges.add(Pair.of(start, end));
        }
        return ranges;
    }
}
