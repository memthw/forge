package me.mthw.forge.ingest.analyzer;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;

import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.AnalysisResult;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;

import me.mthw.forge.Attribute;
import me.mthw.forge.ingest.ForgeIngestFactory;

import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.Score;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.Volume;

/**
 * Abstract class representing an Analyzer that processes files or volumes and interacts with the Blackboard to create and manage artifacts and attributes.
 */
public abstract class Analyzer
{
    protected Blackboard blackboard;
    protected IngestJobContext context;

    protected String moduleName;
    protected BlackboardArtifact.Type artifactType;
    protected HashMap<String, Attribute> attributesMap;
    protected BlackboardAttribute.Type mainAttribute;

    /**
     * Constructs an Analyzer object to process and analyze data during an ingest job.
     *
     * @param mainAtttribute The main attribute type to be analyzed.
     * @param blackboard The blackboard instance used for storing artifacts and attributes.
     * @param context The context of the current ingest job.
     * @throws BlackboardException If there is an error interacting with the blackboard.
     */
    public Analyzer(BlackboardAttribute.Type mainAtttribute, Blackboard blackboard, IngestJobContext context) throws BlackboardException
    {
        this.blackboard = blackboard;
        this.mainAttribute = mainAtttribute;
        moduleName = ForgeIngestFactory.getModuleName();
        this.context = context;

        // attributesList = new ArrayList<Attribute>();
        attributesMap = new HashMap<String, Attribute>();
        createAttributes();
        createArtifact();
        addAttributesToBlackBoard();

    }

    /**
     * Processes the given file and performs analysis on it.
     *
     * @param file The file to be processed, represented as an AbstractFile.
     * @return true if the processing is successful, false otherwise.
     * @throws TskCoreException If there is an error with the Sleuth Kit core.
     * @throws BlackboardException If there is an error interacting with the blackboard.
     * @throws IOException If an I/O error occurs during processing.
     * @throws IllegalAccessError If there is an illegal access error during processing.
     * @throws NoCurrentCaseException If there is no current case available for processing.
     */
    public abstract boolean process(AbstractFile file) throws TskCoreException, BlackboardException, IOException, IllegalAccessError, NoCurrentCaseException;

    /**
     * Processes the given volume and performs analysis on it.
     *
     * @param volume The volume to be processed.
     * @return true if the processing is successful, false otherwise.
     * @throws TskCoreException If an error occurs in the Sleuth Kit core.
     * @throws BlackboardException If an error occurs while posting to the blackboard.
     * @throws IOException If an I/O error occurs during processing.
     * @throws IllegalAccessError If the method is accessed in an illegal context.
     * @throws NoCurrentCaseException If there is no current case available for processing.
     */
    public abstract boolean process(Volume volume) throws TskCoreException, BlackboardException, IOException, IllegalAccessError, NoCurrentCaseException;

    /**
     * Creates an artifact as part of the analysis process. This method is abstract and must be implemented by subclasses to define the specific name for the artifact. The
     * subclass should call createArtifact(String typeName, String displayName, BlackboardArtifact.Category category)
     *
     * @throws BlackboardException if an error occurs during artifact creation.
     */
    protected abstract void createArtifact() throws BlackboardException;

    /**
     * Abstract method to create and fill attributesMap for the analyzer. Subclasses must provide an implementation for this method to define the specific attributes required
     * for their analysis process.
     */
    protected abstract void createAttributes();

    /**
     * Adds attributes from the attributes map to the blackboard. For each attribute in the map, it retrieves or creates the corresponding attribute type in the blackboard
     * and assigns it to the attribute. Map is filled by each subclass in the createAttributes() method.
     *
     * @throws BlackboardException if an error occurs while interacting with the blackboard.
     */
    protected void addAttributesToBlackBoard() throws BlackboardException
    {
        for (Attribute attribute : attributesMap.values())
            attribute.blackoardAttributeType = blackboard.getOrAddAttributeType(attribute.typeName, attribute.type, attribute.displayName);
    }

    /**
     * Adds an artifact to the blackboard with the specified attributes, conclusion, and justification. This method uses a default score of SCORE_LIKELY_NOTABLE and does not
     * include a configuration string.
     *
     * @param file The content file associated with the artifact.
     * @param attributes A list of blackboard attributes to associate with the artifact.
     * @param conclusion A conclusion or summary about the artifact.
     * @param justification A justification or explanation for the conclusion.
     * @throws TskCoreException If there is an error adding the artifact to the blackboard.
     * @throws BlackboardException If there is an error interacting with the blackboard.
     */
    protected void addArtifact(Content file, List<BlackboardAttribute> attributes, String conclusion, String justification) throws TskCoreException, BlackboardException
    {
        addArtifact(file, attributes, conclusion, Score.SCORE_LIKELY_NOTABLE, null, justification);
    }

    /**
     * Adds an artifact to the blackboard with the specified attributes, conclusion, and score and does not include a configuration and justification string.
     *
     * @param file The content file to associate with the artifact.
     * @param attributes A list of blackboard attributes to include in the artifact.
     * @param conclusion A conclusion or summary about the artifact.
     * @param score The score or priority level associated with the artifact.
     * @throws TskCoreException If there is an error adding the artifact to the blackboard.
     * @throws BlackboardException If there is an error interacting with the blackboard.
     */
    protected void addArtifact(Content file, List<BlackboardAttribute> attributes, String conclusion, Score score) throws TskCoreException, BlackboardException
    {
        addArtifact(file, attributes, conclusion, score, null, null);
    }

    /**
     * Adds an artifact to the blackboard with the specified attributes and conclusion. This method uses a default score of SCORE_LIKELY_NOTABLE and does not include a
     * configuration and justification string.
     *
     * @param file The content file associated with the artifact.
     * @param attributes A list of blackboard attributes to associate with the artifact.
     * @param conclusion A conclusion or description for the artifact.
     * @throws TskCoreException If there is an error adding the artifact to the blackboard.
     * @throws BlackboardException If there is an error posting the artifact to the blackboard.
     */
    protected void addArtifact(Content file, List<BlackboardAttribute> attributes, String conclusion) throws TskCoreException, BlackboardException
    {
        addArtifact(file, attributes, conclusion, Score.SCORE_LIKELY_NOTABLE, null, null);
    }

    /**
     * Adds an analysis result artifact to the specified content file, removing any existing analysis results of the same type beforehand.
     *
     * @param file The content file to which the artifact will be added.
     * @param attributes A list of attributes to associate with the artifact.
     * @param conclusion A conclusion string describing the analysis result.
     * @param score The score representing the significance of the analysis result.
     * @param configuration The configuration string associated with the analysis.
     * @param justification The justification string explaining the analysis result.
     * @throws TskCoreException If an error occurs while interacting with the Sleuth Kit database.
     * @throws BlackboardException If an error occurs while posting the artifact to the blackboard.
     */
    protected void addArtifact(Content file, List<BlackboardAttribute> attributes, String conclusion, Score score, String configuration, String justification) throws TskCoreException, BlackboardException
    {
        List<AnalysisResult> results = file.getAnalysisResults(artifactType);
        for (AnalysisResult result : results)
        {
            blackboard.deleteAnalysisResult(result);
        }
        BlackboardArtifact artifact = file.newAnalysisResult(artifactType, score, conclusion, configuration, justification, attributes).getAnalysisResult();
        blackboard.postArtifact(artifact, moduleName, context.getJobId());
    }

    /**
     * Retrieves the {@link BlackboardAttribute.Type} associated with the specified type name.
     *
     * @param typeName The name of the type for which the attribute type is to be retrieved.
     * @return The {@link BlackboardAttribute.Type} corresponding to the given type name,
     *         or {@code null} if the type name is not found in the attributes map.
     */
    public BlackboardAttribute.Type getAttributeType(String typeName)
    {
        return attributesMap.get(typeName).blackoardAttributeType;
    }

    /**
     * Creates an artifact with the specified type name, display name, and assigns it
     * to the default category of analysis results.
     *
     * @param typeName    The type name of the artifact to be created.
     * @param displayName The display name of the artifact to be created.
     * @throws BlackboardException If an error occurs while creating the artifact.
     */
    protected void createArtifact(String typeName, String displayName) throws BlackboardException
    {
        createArtifact(typeName, displayName, BlackboardArtifact.Category.ANALYSIS_RESULT);
    }

    /**
     * Creates or retrieves a blackboard artifact type with the specified type name,
     * display name, and category. If the artifact type does not already exist, it
     * will be added to the blackboard.
     *
     * @param typeName    The unique name of the artifact type.
     * @param displayName The human-readable name of the artifact type.
     * @param category    The category of the artifact type.
     * @throws BlackboardException If there is an error creating or retrieving the artifact type.
     */
    protected void createArtifact(String typeName, String displayName, BlackboardArtifact.Category category) throws BlackboardException
    {
        artifactType = blackboard.getOrAddArtifactType(typeName, displayName, category);
    }
}
