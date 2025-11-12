package me.mthw.forge.ingest.analyzer.volume;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.LayoutFile;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.TskFileRange;
import org.sleuthkit.datamodel.Volume;
import org.sleuthkit.datamodel.VolumeSystem;
import org.sleuthkit.datamodel.blackboardutils.attributes.BlackboardJsonAttrUtil;

import me.mthw.forge.Attribute;
import me.mthw.forge.ingest.ForgeIngestFactory;
import me.mthw.forge.ingest.analyzer.Analyzer;
import me.mthw.forge.utils.Utils;

//https://github.com/libyal/libbde/blob/main/documentation/BitLocker%20Drive%20Encryption%20(BDE)%20format.asciidoc
/**
 * The VolumeAnalyzerBitlocker class is a specialized implementation of the Analyzer
 * class designed to process volumes and extract metadata related to BitLocker encryption.
 * This class is responsible for identifying and analyzing BitLocker-protected volumes,
 * extracting encryption details, and creating blackboard artifacts for forensic analysis.
 *
 * Key Features:
 * - Processes volumes to extract BitLocker metadata, including encryption methods,
 *   creation times, and metadata entries.
 * - Identifies and processes BitLocker keys and descriptions.
 * - Converts extracted metadata into blackboard attributes for forensic analysis.
 * - Creates or updates layout files to make attributes visible in the user interface.
 * - Supports the creation of blackboard artifacts for BitLocker volumes.
 *
 *
 * Attributes:
 * - FORGE_BITLOCKER_KEY_GUID: Represents the GUID of the BitLocker key.
 * - FORGE_BITLOCKER_KEY_PROTECTION_TYPE: Describes the type of key protection used.
 * - FORGE_BITLOCKER_ENCRYPTION_METHOD: Specifies the encryption method of the volume.
 * - FORGE_BITLOCKER_DESCRIPTION: Provides a description of the volume.
 * - FORGE_BITLOCKER_KEY: Contains the keys in JSON format.
 *
 * Exceptions:
 * - TskCoreException: Thrown when an error occurs while interacting with the Sleuth Kit.
 * - BlackboardException: Thrown when an error occurs while adding attributes to the blackboard.
 * - IOException: Thrown when an I/O error occurs while reading the volume.
 * - IllegalAccessError: Thrown when there is an illegal access error.
 * - NoCurrentCaseException: Thrown when there is no current case available.
 *
 * Reference:
 * For more details on the BitLocker Drive Encryption (BDE) format, refer to:
 * https://github.com/libyal/libbde/blob/main/documentation/BitLocker%20Drive%20Encryption%20(BDE)%20format.asciidoc
 *
 */
public class VolumeAnalyzerBitlocker extends Analyzer
{

    public VolumeAnalyzerBitlocker(BlackboardAttribute.Type mainAttribute, Blackboard blackboard, IngestJobContext context) throws BlackboardException
    {
        super(mainAttribute, blackboard, context);
    }

    /**
     * Processes the given abstract file. This method is not supported for the
     * VolumeAnalyzerBitlocker class and will always throw an 
     * UnsupportedOperationException.
     *
     * @param file The abstract file to process.
     * @throws UnsupportedOperationException Always thrown to indicate that this
     *         operation is not supported.
     */
    @Override
    public boolean process(AbstractFile file)
    {
        throw new UnsupportedOperationException("Content type AbstractFile not supported on volume analyzer");
    }

    /**
     * Processes a given volume to extract BitLocker metadata and attributes.
     *
     * @param volume The volume to process.
     * @return true if the processing is successful.
     * @throws TskCoreException         If an error occurs while interacting with the Sleuth Kit.
     * @throws BlackboardException      If an error occurs while adding attributes to the blackboard.
     * @throws IOException              If an I/O error occurs while reading the volume.
     * @throws IllegalAccessError       If there is an illegal access error.
     * @throws NoCurrentCaseException   If there is no current case available.
     *
     * This method performs the following steps:
     * - Reads and parses the BitLocker metadata from the volume.
     * - Extracts encryption method, creation time, and metadata entries.
     * - Identifies and processes BitLocker keys and descriptions.
     * - Converts extracted metadata into blackboard attributes.
     * - Creates or updates a layout file for the volume to make attributes visible in the UI.
     * - Adds the extracted attributes and metadata as artifacts to the case.
     */
    @Override
    public boolean process(Volume volume) throws TskCoreException, BlackboardException, IOException, IllegalAccessError, NoCurrentCaseException
    {
        byte[] longBuffer = new byte[8];
        byte[] intBuffer = new byte[4];
        volume.read(longBuffer, 176, 8);
        Long fveMetadataOffset = Utils.readLong(longBuffer, 0);

        volume.read(intBuffer, fveMetadataOffset + 64, 4);
        int fveMetadataSize = Utils.readInt(intBuffer, 0);

        volume.read(intBuffer, fveMetadataOffset + 64 + 36, 8);
        int encryptionMethod = Utils.readInt(intBuffer, 0); // LSB

        volume.read(longBuffer, fveMetadataOffset + 64 + 40, 8);
        long creationTime = Utils.readLong(longBuffer, 0);
        creationTime = (creationTime - 116444736000000000L) / 10000000L; // MS FILETIME to epoch

        int dataSize = fveMetadataSize - 48 - 64;
        byte[] metadata = new byte[dataSize];
        volume.read(metadata, fveMetadataOffset + 48 + 64, dataSize);
        int offset = 0;
        String description = "";
        BitlockerKeys keys = new BitlockerKeys();
        while (offset < dataSize)
        {
            short size = Utils.readShort(metadata, offset);
            short entryType = Utils.readShort(metadata, offset + 2);
            short valueType = Utils.readShort(metadata, offset + 4);

            int dataOffset = 8;
            if ((entryType == 0x0002) && (valueType == 0x0008))
            {
                BitlockerKey key = new BitlockerKey();
                byte[] guid = new byte[16];
                System.arraycopy(metadata, offset + dataOffset, guid, 0, 16);
                key.FORGE_BITLOCKER_KEY_GUID = guidToString(guid);
                short protectionType = Utils.readShort(metadata, offset + dataOffset + 26);
                key.FORGE_BITLOCKER_KEY_PROTECTION_TYPE = getProtectionTypeName(protectionType);
                keys.keyList.add(key);
                offset += size;
                continue;
            }
            if ((entryType == 0x0007) && (valueType == 0x0002))
            {
                byte[] strByte = new byte[size - dataOffset];
                System.arraycopy(metadata, offset + dataOffset, strByte, 0, size - dataOffset);
                description += new String(strByte, "UTF-16LE");
                offset += size;
                continue;
            }
            offset += size;
        }

        String encryptionMethodStr = getEncryptionMethodName(encryptionMethod);
        List<BlackboardAttribute> attributes = new ArrayList<BlackboardAttribute>();
        attributes.add(BlackboardJsonAttrUtil.toAttribute(getAttributeType("FORGE_BITLOCKER_KEY"), moduleName, keys));
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_BITLOCKER_ENCRYPTION_METHOD"), moduleName, encryptionMethodStr));
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_BITLOCKER_DESCRIPTION"), moduleName, description));

        // Add layout file so attributes are visible in the UI
        long blockSize = ((VolumeSystem) volume.getParent()).getBlockSize();
        long start = volume.getStart() * blockSize;
        long end = (volume.getStart() + volume.getLength()) * blockSize;
        List<TskFileRange> ranges = new ArrayList<TskFileRange>();
        ranges.add(new TskFileRange(start, end, 0));
        LayoutFile layoutFile = null;
        for (Content content : volume.getChildren())
            if (content instanceof LayoutFile && content.getName().startsWith("(BitLocker)"))
            {
                layoutFile = (LayoutFile) content;
                break;
            }
        if (layoutFile == null)
            layoutFile = Case.getCurrentCase().getSleuthkitCase().addLayoutFile("(BitLocker) " + description, volume.getSize(), TSK_FS_NAME_FLAG_ENUM.ALLOC, TSK_FS_META_FLAG_ENUM.USED, 0, creationTime, 0, 0, ranges, volume);

        ForgeIngestFactory.addMainFlag(layoutFile, mainAttribute);
        addArtifact(layoutFile, attributes, "Bitlocker Volume", "Bitlocker volume found");
        return true;
    }

    /**
     * Creates a blackboard artifact for a Bitlocker volume.
     * 
     * @throws BlackboardException if there is an error creating the artifact on the blackboard.
     */
    @Override
    protected void createArtifact() throws BlackboardException
    {
        createArtifact("FORGE_VOLUME_BITLOCKER", "FORGE Bitlocker Volume");
    }

    /**
     * Initializes and populates the attributes map with predefined attributes
     * related to BitLocker volume analysis. Each attribute is associated with
     * a unique key, a type, and a description.
     *
     * Attributes added:
     * - FORGE_BITLOCKER_KEY_GUID: Represents the GUID of the BitLocker key.
     * - FORGE_BITLOCKER_KEY_PROTECTION_TYPE: Describes the type of key protection used.
     * - FORGE_BITLOCKER_ENCRYPTION_METHOD: Specifies the encryption method of the volume.
     * - FORGE_BITLOCKER_DESCRIPTION: Provides a description of the volume.
     * - FORGE_BITLOCKER_KEY: Contains the keys in JSON format.
     */
    @Override
    protected void createAttributes()
    {
        attributesMap.put("FORGE_BITLOCKER_KEY_GUID", new Attribute("FORGE_BITLOCKER_KEY_GUID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Key GUID"));
        attributesMap.put("FORGE_BITLOCKER_KEY_PROTECTION_TYPE", new Attribute("FORGE_BITLOCKER_KEY_PROTECTION_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Key protection"));
        attributesMap.put("FORGE_BITLOCKER_ENCRYPTION_METHOD", new Attribute("FORGE_BITLOCKER_ENCRYPTION_METHOD", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Volume encryption method"));
        attributesMap.put("FORGE_BITLOCKER_DESCRIPTION", new Attribute("FORGE_BITLOCKER_DESCRIPTION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Volume description"));
        attributesMap.put("FORGE_BITLOCKER_KEY", new Attribute("FORGE_BITLOCKER_KEY", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON, "Keys"));
    }

    /**
     * Converts a GUID (Globally Unique Identifier) represented as a byte array
     * into its string representation in the standard GUID format.
     *
     * The format of the resulting string is:
     * XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
     * where each X represents a hexadecimal digit.
     *
     * The byte array is expected to be in little-endian order for the first
     * three groups of bytes, and big-endian order for the remaining groups.
     *
     * @param guid A byte array representing the GUID. It must be at least 16 bytes long.
     * @return A string representation of the GUID in the standard format.
     * @throws ArrayIndexOutOfBoundsException if the input array is shorter than 16 bytes.
     */
    private String guidToString(byte[] guid)
    {

        StringBuilder sb = new StringBuilder();
        for (int i = 3; i >= 0; i--)
            sb.append(String.format("%02X", guid[i]));

        sb.append("-");
        for (int i = 5; i >= 4; i--)
            sb.append(String.format("%02X", guid[i]));

        sb.append("-");
        for (int i = 7; i >= 6; i--)
            sb.append(String.format("%02X", guid[i]));

        sb.append("-");
        for (int i = 8; i < 10; i++)
            sb.append(String.format("%02X", guid[i]));

        sb.append("-");
        for (int i = 10; i < 16; i++)
            sb.append(String.format("%02X", guid[i]));

        return sb.toString();
    }

    /**
     * Returns the name of the protection type based on the provided protection type code.
     *
     * @param protectionType The short value representing the protection type code.
     * @return A string representing the name of the protection type. If the protection type
     *         code is not recognized, "Unknown" is returned.
     */
    private String getProtectionTypeName(short protectionType)
    {
        switch (protectionType)
        {
        case 0x0000:
            return "Clear key (unprotected)";
        case 0x0100:
            return "TPM";
        case 0x0200:
            return "startup key";
        case 0x0500:
            return "TPM + PIN";
        case 0x0800:
            return "Recovery pasword";
        case 0x2000:
            return "Password";
        default:
            return "Unknown";
        }
    }

    /**
     * Retrieves the name of the encryption method based on the provided encryption method identifier.
     *
     * @param encryptionMethod An integer representing the encryption method identifier. The lower 16 bits of this integer are used to determine the encryption method.
     * @return A string describing the encryption method. If the identifier is not recognized, "Unknown" is returned. Specific encryption methods include AES-CBC, AES-XTS,
     * and others, with varying key sizes and configurations.
     */
    private String getEncryptionMethodName(int encryptionMethod)
    {
        short encryptionMethodShort = (short) (encryptionMethod & 0xFFFF);
        switch (encryptionMethodShort)
        {
        case 0x0001:
            return "Unknown (Stretch key)";
        case 0x1001:
            return "Unknown (Stretch key)";
        case 0x2000:
            return "Unknown (AES-CCM 256 bit encryption)";
        case 0x2001:
            return "Unknown (AES-CCM 256 bit encryption)";
        case 0x2002:
            return "Unknown (AES-CCM 256 bit encryption)";
        case 0x2003:
            return "Unknown (AES-CCM 256 bit encryption)";
        case 0x2004:
            return "Unknown (AES-CCM 256 bit encryption)";
        case 0x2005:
            return "Unknown (AES-CCM 256 bit encryption)";
        case (short) 0x8000:
            return "AES-CBC 128-bit encryption with Elephant Diffuser";
        case (short) 0x8001:
            return "AES-CBC 256-bit encryption with Elephant Diffuser";
        case (short) 0x8002:
            return "AES-CBC 128-bit encryption";
        case (short) 0x8003:
            return "AES-CBC 256-bit encryption";
        case (short) 0x8004:
            return "AES-XTS 128-bit encryption";
        case (short) 0x8005:
            return "Unknown (AES-XTS 256-bit encryption)";
        default:
            return "Unknown";
        }
    }

    /**
     * Represents a BitLocker key with associated metadata for creating json blackboard attribute.
     */
    public class BitlockerKey
    {
        public String FORGE_BITLOCKER_KEY_GUID;
        public String FORGE_BITLOCKER_KEY_PROTECTION_TYPE;
    }

    /**
     * Represents a collection of Bitlocker keys for creating json blackboard attribute. This class contains a list of {@link BitlockerKey} objects.
     */
    public class BitlockerKeys
    {
        public List<BitlockerKey> keyList = new ArrayList<>();
    }

}
