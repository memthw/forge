package me.mthw.forge.ingest.analyzer.volume;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.json.JSONObject;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;

import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.LayoutFile;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskFileRange;
import org.sleuthkit.datamodel.Volume;
import org.sleuthkit.datamodel.VolumeSystem;

import me.mthw.forge.Attribute;
import me.mthw.forge.ingest.ForgeIngestFactory;
import me.mthw.forge.ingest.analyzer.Analyzer;
import me.mthw.forge.utils.Utils;

/**
 * The VolumeAnalyzerLUKS class is responsible for analyzing and extracting metadata
 * from LUKS (Linux Unified Key Setup) encrypted volumes. It extends the Analyzer
 * class and provides specific implementations for handling LUKS volumes of version 1
 * and version 2. The extracted metadata includes encryption method, encryption mode,
 * hash method, key size, active key slots, and GUID.
 *
 * Attributes Defined:
 * - FORGE_VOLUME_LUKS_VERSION: Represents the LUKS version (integer).
 * - FORGE_LUKS_ENCRYPTION_METHOD: Specifies the encryption method used (string).
 * - FORGE_LUKS_ENCRYPTION_MODE: Specifies the encryption mode used (string).
 * - FORGE_LUKS_HASH_METHOD: Specifies the hash method used (string).
 * - FORGE_LUKS_KEY_SIZE: Represents the size of the encryption key in bits (integer).
 * - FORGE_LUKS_ACTIVE_KEYSLOTS: Lists the active key slots (string).
 * - FORGE_LUKS_GUID: Represents the globally unique identifier (GUID) of the LUKS volume (string).
 *
 * Exceptions:
 * - TskCoreException: Thrown if there is an error interacting with the Sleuth Kit core.
 * - BlackboardException: Thrown if there is an error adding attributes to the blackboard.
 * - IOException: Thrown if there is an error reading from the volume.
 * - IllegalAccessError: Thrown if there is an illegal access error.
 * - NoCurrentCaseException: Thrown if there is no current case available.
 * 
 * For more details, refer to the LUKS specification at:
 * https://gitlab.com/cryptsetup/cryptsetup#specification-and-documentation
 */
public class VolumeAnalyzerLUKS extends Analyzer
{

    public VolumeAnalyzerLUKS(BlackboardAttribute.Type mainAttribute, Blackboard blackboard, IngestJobContext context) throws BlackboardException
    {
        super(mainAttribute, blackboard, context);
    }

    /**
     * Processes the given file. This implementation does not support processing
     * files of type {@link AbstractFile} and will throw an 
     * {@link UnsupportedOperationException}.
     *
     * @param file the file to be processed
     * @return always throws an exception, so no value is returned
     * @throws UnsupportedOperationException if this method is called, as 
     *         {@link AbstractFile} is not supported by this volume analyzer
     */
    @Override
    public boolean process(AbstractFile file)
    {
        throw new UnsupportedOperationException("Content type AbstractFile not supported on volume analyzer");
    }

    /**
     * Processes a given volume to analyze and extract LUKS (Linux Unified Key Setup) metadata.
     * This method identifies the LUKS version and extracts relevant attributes such as encryption
     * method, encryption mode, hash method, key size, active key slots, and GUID. It also creates
     * a layout file for the LUKS volume to make the attributes visible in the UI.
     *
     * @param volume The volume to be analyzed.
     * @return True if the volume is successfully processed as a LUKS volume, false otherwise.
     * @throws TskCoreException If there is an error interacting with the Sleuth Kit core.
     * @throws BlackboardException If there is an error adding attributes to the blackboard.
     * @throws IOException If there is an error reading from the volum/.
     * @throws IllegalAccessError If there is an illegal access error.
     * @throws NoCurrentCaseException If there is no current case available.
     */
    @Override
    public boolean process(Volume volume) throws TskCoreException, BlackboardException, IOException, IllegalAccessError, NoCurrentCaseException
    {
        byte[] shortBuffer = new byte[2];
        byte[] intBuffer = new byte[4];
        byte[] longBuffer = new byte[8];
        byte[] strBuffer = new byte[32];

        //Read the first 2 bytes to get the version
        volume.read(shortBuffer, 6, 2);
        short version = Utils.readShortBE(shortBuffer, 0);

        List<BlackboardAttribute> attributes = new ArrayList<BlackboardAttribute>();
        // Version 1 
        if (version == 1)
        {
            volume.read(strBuffer, 8, 32);
            String cipherName = new String(strBuffer).trim();

            volume.read(strBuffer, 40, 32);
            String cipherMode = new String(strBuffer).trim();

            volume.read(strBuffer, 72, 32);
            String hash = new String(strBuffer).trim();

            volume.read(intBuffer, 108, 32);
            int keyBytes = Utils.readIntBE(intBuffer, 0);

            byte[] guidBuffer = new byte[40];
            volume.read(guidBuffer, 168, 40);
            String guid = new String(guidBuffer).trim();

            byte[] keySlotBuffer = new byte[48];
            String activeKeySlots = "";
            for (int i = 0; i <= 7; i++)
            {
                volume.read(keySlotBuffer, 208 + (i * 48), 48);
                int status = Utils.readIntBE(keySlotBuffer, 0);
                //slot active
                if (status == 0x00ac71f3)
                {
                    if (activeKeySlots.length() > 0)
                        activeKeySlots += ", ";
                    activeKeySlots += String.format("%d", i);
                }
            }
            attributes.add(new BlackboardAttribute(getAttributeType("FORGE_LUKS_ENCRYPTION_METHOD"), moduleName, cipherName));
            attributes.add(new BlackboardAttribute(getAttributeType("FORGE_LUKS_ENCRYPTION_MODE"), moduleName, cipherMode));
            attributes.add(new BlackboardAttribute(getAttributeType("FORGE_LUKS_HASH_METHOD"), moduleName, hash));
            attributes.add(new BlackboardAttribute(getAttributeType("FORGE_LUKS_KEY_SIZE"), moduleName, keyBytes * 8));
            attributes.add(new BlackboardAttribute(getAttributeType("FORGE_LUKS_ACTIVE_KEYSLOTS"), moduleName, activeKeySlots));
            attributes.add(new BlackboardAttribute(getAttributeType("FORGE_LUKS_GUID"), moduleName, guid));
            attributes.add(new BlackboardAttribute(getAttributeType("FORGE_VOLUME_LUKS_VERSION"), moduleName, 1));

        }
        //Version 2
        else if (version == 2)
        {
            byte[] guidBuffer = new byte[40];
            volume.read(guidBuffer, 168, 40);
            String guid = new String(guidBuffer).trim();

            volume.read(longBuffer, 8, 8);
            long jsonSize = Utils.readLongBE(longBuffer, 0);

            byte[] jsonBuffer = new byte[(int) jsonSize];
            volume.read(jsonBuffer, 4096, (int) jsonSize);
            String json = new String(jsonBuffer).trim();

            //Parse the JSON metadata
            JSONObject root = new JSONObject(json);
            JSONObject keyslots = root.getJSONObject("keyslots");

            String activeKeySlots = "";
            int keySize = 0;
            Iterator<String> keys = keyslots.keys();

            while (keys.hasNext())
            {
                String key = keys.next();
                if (activeKeySlots.length() > 0)
                    activeKeySlots += ", ";
                activeKeySlots += key;
                if (keySize == 0)
                {
                    JSONObject keyslot = keyslots.getJSONObject(key);
                    if (keyslot.has("key_size"))
                    {
                        keySize = keyslot.getInt("key_size");
                    }
                }
            }

            JSONObject segments = root.getJSONObject("segments");
            String encryptionMethod = "";
            keys = segments.keys();
            if (keys.hasNext() == true)
            {
                String firstKey = keys.next();
                JSONObject digestEntry = segments.getJSONObject(firstKey);
                encryptionMethod = digestEntry.getString("encryption");
            }

            String encryptionMode = "";
            int dashIndex = encryptionMethod.indexOf('-');
            if (dashIndex != -1)
            {
                encryptionMode = encryptionMethod.substring(dashIndex + 1);
                encryptionMethod = encryptionMethod.substring(0, dashIndex);
            }

            JSONObject digests = root.getJSONObject("digests");
            String hash = "";

            // Get the first key
            keys = digests.keys();
            if (keys.hasNext() == true)
            {
                String firstKey = keys.next();
                JSONObject digestEntry = digests.getJSONObject(firstKey);
                hash = digestEntry.getString("hash");
            }

            attributes.add(new BlackboardAttribute(getAttributeType("FORGE_LUKS_ENCRYPTION_METHOD"), moduleName, encryptionMethod));
            attributes.add(new BlackboardAttribute(getAttributeType("FORGE_LUKS_ENCRYPTION_MODE"), moduleName, encryptionMode));
            attributes.add(new BlackboardAttribute(getAttributeType("FORGE_LUKS_HASH_METHOD"), moduleName, hash));
            attributes.add(new BlackboardAttribute(getAttributeType("FORGE_LUKS_KEY_SIZE"), moduleName, keySize * 8));
            attributes.add(new BlackboardAttribute(getAttributeType("FORGE_LUKS_ACTIVE_KEYSLOTS"), moduleName, activeKeySlots));
            attributes.add(new BlackboardAttribute(getAttributeType("FORGE_LUKS_GUID"), moduleName, guid));
            attributes.add(new BlackboardAttribute(getAttributeType("FORGE_VOLUME_LUKS_VERSION"), moduleName, 2));
        }
        else
        {
            return false;
        }

        // Create a layout file for the LUKS volume so attributes are visible in the UI
        long blockSize = ((VolumeSystem) volume.getParent()).getBlockSize();
        long start = volume.getStart() * blockSize;
        long end = (volume.getStart() + volume.getLength()) * blockSize;
        List<TskFileRange> ranges = new ArrayList<TskFileRange>();
        ranges.add(new TskFileRange(start, end, 0));
        LayoutFile layoutFile = null;
        for (Content content : volume.getChildren())
            if (content instanceof LayoutFile && content.getName().startsWith("(LUKS)"))
            {
                layoutFile = (LayoutFile) content;
                break;
            }
        if (layoutFile == null)
            layoutFile = Case.getCurrentCase().getSleuthkitCase().addLayoutFile("(LUKS)", volume.getSize(), TSK_FS_NAME_FLAG_ENUM.ALLOC, TSK_FS_META_FLAG_ENUM.USED, 0, 0, 0, 0, ranges, volume);

        ForgeIngestFactory.addMainFlag(layoutFile, mainAttribute);
        addArtifact(layoutFile, attributes, "LUKS Volume", "LUKS volume found");
        return true;
    }

    /**
     * Creates an artifact representing a LUKS (Linux Unified Key Setup) volume.
     * This method overrides the base class implementation to specify the artifact
     * type and description for LUKS volumes.
     *
     * @throws BlackboardException if there is an error during artifact creation.
     */
    @Override
    protected void createArtifact() throws BlackboardException
    {
        createArtifact("FORGE_VOLUME_LUKS", "FORGE LUKS Volume");
    }

    /**
     * Initializes and populates the attributes map with LUKS volume-specific attributes.
     * Each attribute is defined with a unique key, a type, and a description.
     * 
     * Attributes added:
     * - FORGE_VOLUME_LUKS_VERSION: Represents the LUKS version (integer).
     * - FORGE_LUKS_ENCRYPTION_METHOD: Specifies the encryption method used (string).
     * - FORGE_LUKS_ENCRYPTION_MODE: Specifies the encryption mode used (string).
     * - FORGE_LUKS_HASH_METHOD: Specifies the hash method used (string).
     * - FORGE_LUKS_KEY_SIZE: Represents the size of the encryption key in bits (integer).
     * - FORGE_LUKS_ACTIVE_KEYSLOTS: Lists the active key slots (string).
     * - FORGE_LUKS_GUID: Represents the globally unique identifier (GUID) of the LUKS volume (string).
     */
    @Override
    protected void createAttributes()
    {
        attributesMap.put("FORGE_VOLUME_LUKS_VERSION", new Attribute("FORGE_VOLUME_LUKS_VERSION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER, "Version"));
        attributesMap.put("FORGE_LUKS_ENCRYPTION_METHOD", new Attribute("FORGE_LUKS_ENCRYPTION_METHOD", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Encryption method"));
        attributesMap.put("FORGE_LUKS_ENCRYPTION_MODE", new Attribute("FORGE_LUKS_ENCRYPTION_MODE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Encryption mode"));
        attributesMap.put("FORGE_LUKS_HASH_METHOD", new Attribute("FORGE_LUKS_HASH_METHOD", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Hash method"));
        attributesMap.put("FORGE_LUKS_KEY_SIZE", new Attribute("FORGE_LUKS_KEY_SIZE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER, "Key size"));
        attributesMap.put("FORGE_LUKS_ACTIVE_KEYSLOTS", new Attribute("FORGE_LUKS_ACTIVE_KEYSLOTS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Active key slots"));
        attributesMap.put("FORGE_LUKS_GUID", new Attribute("FORGE_LUKS_GUID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "GUID"));
    }

}
