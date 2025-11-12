package me.mthw.forge.ingest.analyzer.file;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.poi.poifs.crypt.EncryptionInfo;
import org.apache.poi.poifs.filesystem.OfficeXmlFileException;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.Volume;
import org.sleuthkit.datamodel.ReadContentInputStream;

import me.mthw.forge.Attribute;
import me.mthw.forge.ingest.ForgeIngestFactory;
import me.mthw.forge.ingest.analyzer.Analyzer;

/**
 * The FileAnalyzerOffice class is responsible for analyzing files to determine if they are encrypted Microsoft Office documents. It utilizes the Apache POI library to
 * inspect the file's encryption details and creates corresponding blackboard attributes and artifacts for further processing.
 *
 * This class extends the Analyzer class and provides specific implementations for processing Office files. It supports the detection of encryption mode, cipher
 * algorithm, and hash algorithm used in encrypted Office documents.
 *
 *
 * Attributes Created: - FORGE_OFFICE_MODE: Represents the encryption mode of the Office file. - FORGE_OFFICE_CYPHER_ALG: Represents the cipher algorithm used. -
 * FORGE_OFFICE_HASH_ALG: Represents the hash algorithm used.
 *
 *
 * Exceptions: - TskCoreException: Thrown if there is an error accessing the file's content. - BlackboardException: Thrown if there is an error creating blackboard
 * attributes or artifacts. - IOException: Thrown if there is an error reading the file. - UnsupportedOperationException: Thrown when attempting to process unsupported
 * content types.
 */
public class FileAnalyzerOffice extends Analyzer
{

    public FileAnalyzerOffice(BlackboardAttribute.Type mainAttribute, Blackboard blackboard, IngestJobContext context) throws BlackboardException
    {
        super(mainAttribute, blackboard, context);
    }

    /**
     * Processes an AbstractFile to determine if it is an encrypted Office document using POI library. If the file is an encrypted Office document, extracts encryption
     * details and creates corresponding blackboard attributes and artifacts.
     *
     * @param file The AbstractFile to be processed.
     * @return true if the file is an encrypted Office document, false otherwise.
     * @throws TskCoreException If there is an error accessing the file's content.
     * @throws BlackboardException If there is an error creating blackboard attributes or artifacts.
     * @throws IOException If there is an error reading the file.
     */
    @Override
    public boolean process(AbstractFile file) throws TskCoreException, BlackboardException, IOException
    {
        POIFSFileSystem fs;
        try
        {
            fs = new POIFSFileSystem(new ReadContentInputStream(file));
        }
        catch (OfficeXmlFileException e)
        {
            // Not OLE File (XML Document not encrypted)
            return false;
        }

        EncryptionInfo encInfo;
        try
        {
            encInfo = new EncryptionInfo(fs);
        }
        catch (IOException e)
        {
            // OLE File Not encrypted
            try
            {
                fs.close();
            }
            catch (IOException e1)
            {
            }
            return false;
        }
        try
        {
            fs.close();
        }
        catch (IOException e)
        {
        }
        List<BlackboardAttribute> attributes = new ArrayList<BlackboardAttribute>();
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_OFFICE_MODE"), moduleName, encInfo.getEncryptionMode().name()));
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_OFFICE_CYPHER_ALG"), moduleName, encInfo.getHeader().getCipherAlgorithm().name()));
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_OFFICE_HASH_ALG"), moduleName, encInfo.getHeader().getHashAlgorithm().name()));

        ForgeIngestFactory.addMainFlag(file, mainAttribute);
        addArtifact(file, attributes, "Encrypted Office Document", "Encrypted Office file found");

        return true;
    }

    /**
     * Creates an artifact with predefined type and description for MS Office files.
     *
     * @throws BlackboardException if there is an error during artifact creation.
     */
    @Override
    protected void createArtifact() throws BlackboardException
    {
        createArtifact("FORGE_OFFICE", "FORGE MS Office");
    }

    /**
     * Creates and populates the attributes map with specific attributes related to office file analysis. Each attribute represents a property of the office file, such as
     * encryption mode, cipher algorithm, and hash algorithm.
     * 
     * Attributes added: - FORGE_OFFICE_MODE: Represents the encryption mode of the office file. - FORGE_OFFICE_CYPHER_ALG: Represents the cipher algorithm used. -
     * FORGE_OFFICE_HASH_ALG: Represents the hash algorithm used.
     */
    @Override
    protected void createAttributes()
    {
        attributesMap.put("FORGE_OFFICE_MODE", new Attribute("FORGE_OFFICE_MODE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Encryption Mode"));
        attributesMap.put("FORGE_OFFICE_CYPHER_ALG", new Attribute("FORGE_OFFICE_CYPHER_ALG", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Cipher Algorithm"));
        attributesMap.put("FORGE_OFFICE_HASH_ALG", new Attribute("FORGE_OFFICE_HASH_ALG", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Hash Algorithm"));
    }

    /**
     * Processes the given volume. This method is not supported for the content type Volume and will always throw an UnsupportedOperationException.
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
