package me.mthw.forge.ingest.analyzer.file;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.Score;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.Volume;

import me.mthw.forge.Attribute;
import me.mthw.forge.ingest.analyzer.Analyzer;
import me.mthw.forge.utils.Utils;

/**
 * The FileAnalyzerStrings class is a specialized implementation of the Analyzer class designed to process files and extract BitLocker recovery keys. It scans files for
 * strings matching a specific pattern that represents a BitLocker recovery key, validates the keys, and adds them as attributes to the blackboard.
 * 
 * 
 * Exceptions: - Throws IllegalArgumentException, TskCoreException, or BlackboardException during processing if errors occur in file interaction or blackboard operations.
 */
public class FileAnalyzerStrings extends Analyzer
{

    public FileAnalyzerStrings(BlackboardAttribute.Type mainAttribute, Blackboard blackboard, IngestJobContext context) throws BlackboardException
    {
        super(mainAttribute, blackboard, context);
    }

    /**
     * Processes the given file to extract and identify potential BitLocker recovery keys. This method scans the file for strings matching a specific pattern that represents
     * a BitLocker recovery key. The pattern consists of eight groups of six digits separated by non-digit characters. Each group must be divisible by 11 for the string to be
     * considered a valid key. Valid keys are then added as attributes to the blackboard.
     * 
     * @param file The file to be processed.
     * @return {@code true} if the processing is successful.
     * @throws IllegalArgumentException
     * @throws TskCoreException If there is an error interacting with the Sleuth Kit core.
     * @throws BlackboardException If there is an error adding attributes to the blackboard..
     */
    @Override
    public boolean process(AbstractFile file) throws TskCoreException, IllegalArgumentException, BlackboardException
    {
        // Regex pattern to match BitLocker recovery key format
        Pattern pattern = Pattern.compile("^.*(\\d{6})\\D(\\d{6})\\D(\\d{6})\\D(\\d{6})\\D(\\d{6})\\D(\\d{6})\\D(\\d{6})\\D(\\d{6}).*$");
        List<String> strings = Utils.extractStringFromFile(file);
        List<String> keys = new ArrayList<>();
        
        // Check if each group is divisible by 11
        for (String string : strings)
        {
            Matcher matcher = pattern.matcher(string);
            if (matcher.find())
            {
                boolean isKey = true;
                for (int i = 1; i <= matcher.groupCount(); i++)
                {
                    int group = Integer.parseInt(matcher.group(i));
                    if ((group % 11) != 0)
                    {
                        isKey = false;
                        break;
                    }
                }
                if (isKey)
                    keys.add(string);
            }
        }

        for (String key : keys)
        {
            List<BlackboardAttribute> attributes = new ArrayList<>();
            attributes.add(new BlackboardAttribute(getAttributeType("FORGE_BITLOCKER_RECOVERY_KEY_DATA"), moduleName, key));
            addArtifact(file, attributes, "BitLocker Recovery Key", null, null, null);
        }
        return true;
    }

    /**
     * Creates a new artifact with the specified type, display name, and category. This method is overridden to define the creation of a specific artifact related to
     * BitLocker Recovery Key.
     *
     * @throws BlackboardException if there is an error during the artifact creation process.
     */
    @Override
    protected void createArtifact() throws BlackboardException
    {
        createArtifact("FORGE_BITLOCKER_RECOVERY_KEY", "BitLocker Recovery Key", BlackboardArtifact.Category.DATA_ARTIFACT);
    }

    /**
     * Creates and populates the attributes map with predefined attributes. This method adds a specific attribute for Bitlocker Recovery Key Data to the attributes map. The
     * attribute includes a name, type, and description.
     */
    @Override
    protected void createAttributes()
    {
        attributesMap.put("FORGE_BITLOCKER_RECOVERY_KEY_DATA", new Attribute("FORGE_BITLOCKER_RECOVERY_KEY_DATA", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Bitlocker Recovery Key Data"));
    }

    /**
     * Adds a new artifact to the blackboard with the specified attributes and metadata.
     *
     * @param file The content file to which the artifact is associated.
     * @param attributes A list of blackboard attributes to include in the artifact.
     * @param conclusion A conclusion or summary related to the artifact.
     * @param score The score or severity associated with the artifact.
     * @param configuration The configuration or context in which the artifact was created.
     * @param justification The justification or reasoning for creating the artifact.
     * @throws TskCoreException If there is an error interacting with the Sleuth Kit core.
     * @throws BlackboardException If there is an error posting the artifact to the blackboard.
     */
    @Override
    protected void addArtifact(Content file, List<BlackboardAttribute> attributes, String conclusion, Score score, String configuration, String justification) throws TskCoreException, BlackboardException
    {
        BlackboardArtifact artifact = blackboard.newDataArtifact(artifactType, file.getId(), file.getDataSource().getId(), attributes, null);
        blackboard.postArtifact(artifact, moduleName, context.getJobId());
    }

    /**
     * Processes the given volume. This method is not supported for the content type Volume in the file analyzer and will always throw an UnsupportedOperationException.
     *
     * @param volume The volume to be processed.
     * @throws UnsupportedOperationException if this method is called, as processing of content type Volume is not supported
     */
    @Override
    public boolean process(Volume volume)
    {
        throw new UnsupportedOperationException("Content type Volume not supported on file analyzer");
    }

}
