package me.mthw.forge.ingest;

import java.io.IOException;
import java.util.logging.Level;

import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.casemodule.services.TagsManager;
import org.sleuthkit.autopsy.casemodule.services.TagsManager.TagNameAlreadyExistsException;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.MessageNotifyUtil;
import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.autopsy.ingest.IngestServices;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;

import me.mthw.forge.ingest.analyzer.file.FileAnalyzerOffice;
import me.mthw.forge.ingest.analyzer.file.FileAnalyzerPDF;
import me.mthw.forge.ingest.analyzer.file.FileAnalyzerStrings;
import me.mthw.forge.ingest.analyzer.file.FileAnalyzerZIPArchive;

import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.TskCoreException;

/**
 * The ForgeFileIngest class implements the FileIngestModule interface and is responsible for analyzing files during the ingest process in the FORGE framework. It
 * initializes various file analyzers for specific file types (e.g., Office documents, PDFs, ZIP archives) and performs string extraction for BitLocker recovery keys. The
 * class also ensures the existence of a custom tag name in the TagsManager for tagging purposes.
 * 
 * Key Features: - Initializes analyzers for Office documents, PDFs, ZIP archives, and string extraction. - Ensures the creation of a custom tag name "FORGE Cracker
 * Source" in the TagsManager. - Processes files based on their MIME type or file extension using appropriate analyzers. - Handles exceptions during initialization and
 * file processing, logging errors and notifying users.
 * 
 * Methods: - `startUp(IngestJobContext context)`: Initializes the module, setting up analyzers, blackboard, and logger, and ensures the existence of the custom tag name.
 * - `process(AbstractFile file)`: Processes a given file, determining its type and delegating analysis to the appropriate analyzer. Handles exceptions and logs errors if
 * processing fails. - `shutDown()`: Cleans up resources when the module is shut down.
 * 
 * Exceptions: - Handles exceptions such as `NoCurrentCaseException`, `BlackboardException`, `TskCoreException`, `IOException`, and `IllegalAccessError` during
 * initialization and file processing.
 */
public class ForgeFileIngest implements FileIngestModule
{
    private Logger logger;
    private Blackboard blackboard;

    private FileAnalyzerOffice officeAnalyzer;
    private FileAnalyzerPDF pdfAnalyzer;
    private FileAnalyzerZIPArchive zipAnalyzer;
    private FileAnalyzerStrings fileAnalyzerStrings;

    BlackboardAttribute.Type mainAttribute;

    ForgeFileIngest()
    {
    }

    /**
     * Initializes the FORGE File Ingest module. This method sets up the necessary components for file analysis and tagging during the ingest process.
     *
     * @param context The context of the ingest job.
     * @throws IngestModuleException If there is an error during initialization, such as issues with the current case or the blackboard.
     *
     * The method performs the following steps: - Retrieves the current case and initializes the blackboard for artifact creation. - Creates instances of file analyzers for
     * Office documents, PDFs, ZIP archives, and string analysis. - Ensures the existence of a custom tag name "FORGE Cracker Source" in the TagsManager. - Initializes the
     * logger for the module.
     */
    @Override
    public void startUp(IngestJobContext context) throws IngestModuleException
    {
        try
        {
            blackboard = Case.getCurrentCaseThrows().getSleuthkitCase().getBlackboard();
            mainAttribute = ForgeIngestFactory.createBlackboardArtifacts(blackboard);

            officeAnalyzer = new FileAnalyzerOffice(mainAttribute, blackboard, context);
            pdfAnalyzer = new FileAnalyzerPDF(mainAttribute, blackboard, context);
            zipAnalyzer = new FileAnalyzerZIPArchive(mainAttribute, blackboard, context);
            fileAnalyzerStrings = new FileAnalyzerStrings(mainAttribute, blackboard, context);

        }
        catch (NoCurrentCaseException | BlackboardException e)
        {
            throw new IngestModuleException("FORGE File module initialization errror", e);
        }

        TagsManager tagsManager;
        try
        {
            tagsManager = Case.getCurrentCaseThrows().getServices().getTagsManager();
            tagsManager.addTagName("FORGE Cracker Source");

        }
        // This is fine, we just need to make sure the tag name exists
        catch (TagNameAlreadyExistsException e)
        {
        }
        catch (NoCurrentCaseException | TskCoreException e)
        {
            throw new IngestModuleException("FORGE File module initialization errror", e);
        }

        logger = IngestServices.getInstance().getLogger(ForgeIngestFactory.getModuleName());
    }

    /**
     * Processes a given file to analyze its content based on its MIME type or file extension.
     * 
     * @param file The file to be processed. Must not be null, a directory, or empty.
     * @return A {@link ProcessResult} indicating the result of the processing. Returns {@code ProcessResult.OK} if the file is successfully processed or skipped, and
     * {@code ProcessResult.ERROR} if an error occurs during processing.
     * 
     * The method performs the following steps: - Validates the file to ensure it is not null, not a directory, and has a size greater than 0. - Reads the first byte of the
     * file to confirm it is readable. - Determines the file's MIME type and extension to decide the appropriate analyzer to use: - PDF files are processed using
     * `pdfAnalyzer`. - ZIP files are processed using `zipAnalyzer`. - Office files (e.g., DOCX, XLSX, PPTX) are processed using `officeAnalyzer`. - Additionally, performs
     * string extraction for BitLocker recovery keys using `fileAnalyzerStrings`.
     * 
     * If an exception occurs during processing, it logs the error and notifies the user.
     * 
     * Exceptions handled: - {@link TskCoreException} - {@link BlackboardException} - {@link IOException} - {@link IllegalAccessError} - {@link NoCurrentCaseException}
     */
    @Override
    public ProcessResult process(AbstractFile file)
    {
        // Make sure file is file and can be read
        if (file == null || file.isDir() || file.getSize() <= 0)
            return ProcessResult.OK;

        byte[] buffer = new byte[1];
        try
        {
            if (file.read(buffer, 0, 1) != 1)
                return ProcessResult.OK;
        }
        catch (TskCoreException e)
        {
            return ProcessResult.OK;
        }

        String mimeType = file.getMIMEType().toLowerCase();
        String ext = file.getNameExtension().toLowerCase();

        boolean processed = false;
        try
        {
            if (mimeType.equals("application/pdf") || mimeType.equals("application/x-pdf") || mimeType.equals("application/x-bzpdf") || mimeType.equals("application/x-gzpdf") || ext.equals("pdf"))
            {
                processed = pdfAnalyzer.process(file);
            }
            else if (mimeType.equals("application/zip") || mimeType.equals("application/x-zip-compressed") || ext.equals("zip"))
            {
                processed = zipAnalyzer.process(file);
            }
            // As seen in autopsy (core/src/org/sleuthkit/autopsy/modules/encryptiondetection/EncryptionDetectionFileIngestModule.java)
            else if (mimeType.equals("application/x-ooxml-protected") || ext.equals("docx") || ext.equals("xlsx") || ext.equals("pptx") || ext.equals("docm") || ext.equals("xlsm") || ext.equals("pptm") || ext.equals("dotx") || ext.equals("xltx") || ext.equals("potx") || ext.equals("dotm") || ext.equals("xltm") || ext.equals("potm"))
            {
                processed = officeAnalyzer.process(file);
            }

            // String extract for bitlocker recovery key
            fileAnalyzerStrings.process(file);

        }
        catch (TskCoreException | BlackboardException | IOException | IllegalAccessError | NoCurrentCaseException e)
        {
            MessageNotifyUtil.Notify.error(": Error processing file: " + file.getName(), e.getMessage());
            logger.log(Level.WARNING, "Error processing file: " + file.getName(), e.getMessage());
            return ProcessResult.ERROR;
        }
        return ProcessResult.OK;
    }

    @Override
    public void shutDown()
    {

    }
}
