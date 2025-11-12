package me.mthw.forge.ingest.analyzer.file;

import java.io.IOException;
import java.util.List;

import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;

import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.Volume;

import me.mthw.forge.Attribute;
import me.mthw.forge.ingest.analyzer.Analyzer;

/**
 * The FileAnalyzerZIPFile class is a specialized implementation of the Analyzer
 * class designed to process and analyze ZIP files.It is only used to create artifact and attributes.
 * Parsing of ZIP files is done in the FileAnalyzerZIPArchive class.
 * 
 * @see Analyzer
 * @see FileAnalyzerZIPArchive
 */
public class FileAnalyzerZIPFile extends Analyzer
{
    public FileAnalyzerZIPFile(BlackboardAttribute.Type mainAttribute, Blackboard blackboard, IngestJobContext context) throws BlackboardException
    {
        super(mainAttribute, blackboard, context);
    }

    @Override
    public boolean process(AbstractFile file) throws TskCoreException, BlackboardException, IOException
    {
        return false;
    }

    @Override
    protected void createArtifact() throws BlackboardException
    {
        createArtifact("FORGE_ZIP_FILE", "FORGE ZIP File");
    }

    /**
     * Initializes and populates the attributesMap with metadata attributes for ZIP files.
     * Each attribute represents a specific property of a ZIP file and is associated with a type and description.
     * 
     * Attributes:
     * - FORGE_ZIP_FILE_VER_MADE: Represents the version of the ZIP file made by. (Type: STRING)
     * - FORGE_ZIP_FILE_VER_EXTRACT: Represents the version required to extract the ZIP file. (Type: STRING)
     * - FORGE_ZIP_FILE_GEN_PURP_FLAG: Represents the general purpose bit flag of the ZIP file. (Type: STRING)
     * - FORGE_ZIP_FILE_COMP_METHOD: Represents the compression method used in the ZIP file. (Type: STRING)
     * - FORGE_ZIP_FILE_LAST_MOD_TIME: Represents the last modified time of the ZIP file. (Type: STRING)
     * - FORGE_ZIP_FILE_LAST_MOD_DATE: Represents the last modified date of the ZIP file. (Type: STRING)
     * - FORGE_ZIP_FILE_CRC32: Represents the CRC32 checksum of the ZIP file. (Type: STRING)
     * - FORGE_ZIP_FILE_COMP_SIZE: Represents the compressed size of the ZIP file. (Type: INTEGER)
     * - FORGE_ZIP_FILE_UNCOMP_SIZE: Represents the uncompressed size of the ZIP file. (Type: INTEGER)
     * - FORGE_ZIP_FILE_INTERNAL_FILE_ATTRIBUTES: Represents the internal file attributes of the ZIP file. (Type: STRING)
     * - FORGE_ZIP_FILE_EXTERNAL_FILE_ATTRIBUTES: Represents the external file attributes of the ZIP file. (Type: STRING)
     * - FORGE_ZIP_FILE_RELATIVE_OFFSET_OF_LOCAL_HEADER: Represents the relative offset of the local header in the ZIP file. (Type: INTEGER)
     * - FORGE_ZIP_FILE_EXTRA_FIELD: Represents the extra field data in the ZIP file. (Type: STRING)
     * - FORGE_ZIP_FILE_FILE_COMMENT: Represents the file comment associated with the ZIP file. (Type: STRING)
     * - FORGE_ZIP_FILE_ROOT_ID: Represents the root file ID of the ZIP file. (Type: LONG)
     * - FORGE_ZIP_FILE_ENCRYPTED: Indicates whether the ZIP file is encrypted. (Type: STRING)
     * - FORGE_ZIP_FILE_ENCRYPTION_METHOD: Represents the encryption method used in the ZIP file. (Type: STRING)
     * - FORGE_ZIP_FILE_PATH: Represents the file path of the ZIP file. (Type: STRING)
     * - FORGE_ZIP_FILE_TYPE: Represents the type of the ZIP file. (Type: STRING)
     */
    @Override
    protected void createAttributes()
    {
        attributesMap.put("FORGE_ZIP_FILE_VER_MADE", new Attribute("FORGE_ZIP_FILE_VER_MADE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Version Made By"));
        attributesMap.put("FORGE_ZIP_FILE_VER_EXTRACT", new Attribute("FORGE_ZIP_FILE_VER_EXTRACT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Version Extract"));
        attributesMap.put("FORGE_ZIP_FILE_GEN_PURP_FLAG", new Attribute("FORGE_ZIP_FILE_GEN_PURP_FLAG", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "General Purpose Bit Flag"));
        attributesMap.put("FORGE_ZIP_FILE_COMP_METHOD", new Attribute("FORGE_ZIP_FILE_COMP_METHOD", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Compression Method"));
        attributesMap.put("FORGE_ZIP_FILE_LAST_MOD_TIME", new Attribute("FORGE_ZIP_FILE_LAST_MOD_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Last Modified Time"));
        attributesMap.put("FORGE_ZIP_FILE_LAST_MOD_DATE", new Attribute("FORGE_ZIP_FILE_LAST_MOD_DATE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Last Modified Date"));
        attributesMap.put("FORGE_ZIP_FILE_CRC32", new Attribute("FORGE_ZIP_FILE_CRC32", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "CRC32"));
        attributesMap.put("FORGE_ZIP_FILE_COMP_SIZE", new Attribute("FORGE_ZIP_FILE_COMP_SIZE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER, "Compressed Size"));
        attributesMap.put("FORGE_ZIP_FILE_UNCOMP_SIZE", new Attribute("FORGE_ZIP_FILE_UNCOMP_SIZE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER, "Uncompressed Size"));
        attributesMap.put("FORGE_ZIP_FILE_INTERNAL_FILE_ATTRIBUTES", new Attribute("FORGE_ZIP_FILE_INTERNAL_FILE_ATTRIBUTES", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Internal File Attributes"));
        attributesMap.put("FORGE_ZIP_FILE_EXTERNAL_FILE_ATTRIBUTES", new Attribute("FORGE_ZIP_FILE_EXTERNAL_FILE_ATTRIBUTES", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "External File Attributes"));
        attributesMap.put("FORGE_ZIP_FILE_RELATIVE_OFFSET_OF_LOCAL_HEADER", new Attribute("FORGE_ZIP_FILE_RELATIVE_OFFSET_OF_LOCAL_HEADER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER, "Relative Offset of Local Header"));
        attributesMap.put("FORGE_ZIP_FILE_EXTRA_FIELD", new Attribute("FORGE_ZIP_FILE_EXTRA_FIELD", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Extra Field"));
        attributesMap.put("FORGE_ZIP_FILE_FILE_COMMENT", new Attribute("FORGE_ZIP_FILE_FILE_COMMENT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Comment"));
        attributesMap.put("FORGE_ZIP_FILE_ROOT_ID", new Attribute("FORGE_ZIP_FILE_ROOT_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "Root file ID"));
        attributesMap.put("FORGE_ZIP_FILE_ENCRYPTED", new Attribute("FORGE_ZIP_FILE_ENCRYPTED", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Encrypted"));
        attributesMap.put("FORGE_ZIP_FILE_ENCRYPTION_METHOD", new Attribute("FORGE_ZIP_FILE_ENCRYPTION_METHOD", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Encryption Method"));
        attributesMap.put("FORGE_ZIP_FILE_PATH", new Attribute("FORGE_ZIP_FILE_PATH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Path"));
        attributesMap.put("FORGE_ZIP_FILE_TYPE", new Attribute("FORGE_ZIP_FILE_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Type"));
    }

    public void addArtifact(AbstractFile file, List<BlackboardAttribute> attributes, String conclusion, String justification) throws TskCoreException, BlackboardException
    {
        addArtifact(file, attributes, conclusion);
    }

    @Override
    public boolean process(Volume volume)
    {
        throw new UnsupportedOperationException("Content type Volume not supported on file analyzer");
    }

}
