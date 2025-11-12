package me.mthw.forge.ingest.ZIP;

import java.util.ArrayList;
import java.util.List;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.DerivedFile;
import org.sleuthkit.datamodel.TimeUtilities;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.TskData.EncodingType;

import me.mthw.forge.ingest.analyzer.Analyzer;
import me.mthw.forge.utils.Utils;

/**
 * Represents a record in the central directory of a ZIP file. This class contains metadata and attributes related to a file or directory stored in a ZIP archive, as well
 * as methods to retrieve and manipulate this data. Names of fields are based on the ZIP file format specification.
 */
public class ZipCentralDirectoryRecord
{
    public short versionMadeBy;
    public short versionNeededToExtract;
    public short generalPurposeBitFlag;
    public String compressionMethod;
    public short lastModFileTime;
    public short lastModFileDate;
    public int crc32;
    public int compressedSize;
    public int uncompressedSize;
    public short fileNameLength;
    public short extraFieldLength;
    public short fileCommentLength;
    public short diskNumberStart;
    public short internalFileAttributes;
    public int externalFileAttributes;
    public int relativeOffsetOfLocalHeader;
    public String fileName; // Path, starts with /
    public String name; // Name
    public byte[] extraField;
    public String fileComment;

    public boolean encrypted;
    public String encryptionMethod = new String();
    public boolean compressed;
    public boolean directory;

    public AbstractFile abstractFile;
    public long rootFileTskID;

    public ZipCentralDirectoryRecord()
    {
    }

    /**
     * Retrieves a list of blackboard attributes for the ZIP central directory record.
     *
     * @param ingestAnalyzer The analyzer used to retrieve attribute types.
     * @param moduleName The name of the module creating the attributes.
     * @return A list of {@link BlackboardAttribute} objects containing metadata about the ZIP central directory record, such as version information, compression method,
     * timestamps, file attributes, and more.
     */
    public List<BlackboardAttribute> getAttributes(Analyzer ingestAnalyzer, String moduleName)
    {
        List<BlackboardAttribute> attributes = new ArrayList<>();
        attributes.add(new BlackboardAttribute(ingestAnalyzer.getAttributeType("FORGE_ZIP_FILE_VER_MADE"), moduleName, getVersionString()));
        attributes.add(new BlackboardAttribute(ingestAnalyzer.getAttributeType("FORGE_ZIP_FILE_VER_EXTRACT"), moduleName, getVersionString()));
        attributes.add(new BlackboardAttribute(ingestAnalyzer.getAttributeType("FORGE_ZIP_FILE_GEN_PURP_FLAG"), moduleName, Utils.toBinString(generalPurposeBitFlag)));
        attributes.add(new BlackboardAttribute(ingestAnalyzer.getAttributeType("FORGE_ZIP_FILE_COMP_METHOD"), moduleName, compressionMethod));
        attributes.add(new BlackboardAttribute(ingestAnalyzer.getAttributeType("FORGE_ZIP_FILE_LAST_MOD_DATE"), moduleName, Utils.convertDosDate(lastModFileDate)));
        attributes.add(new BlackboardAttribute(ingestAnalyzer.getAttributeType("FORGE_ZIP_FILE_LAST_MOD_TIME"), moduleName, Utils.convertDosTime(lastModFileTime)));
        attributes.add(new BlackboardAttribute(ingestAnalyzer.getAttributeType("FORGE_ZIP_FILE_CRC32"), moduleName, Utils.toHexString(crc32)));
        attributes.add(new BlackboardAttribute(ingestAnalyzer.getAttributeType("FORGE_ZIP_FILE_COMP_SIZE"), moduleName, compressedSize));
        attributes.add(new BlackboardAttribute(ingestAnalyzer.getAttributeType("FORGE_ZIP_FILE_UNCOMP_SIZE"), moduleName, uncompressedSize));
        attributes.add(new BlackboardAttribute(ingestAnalyzer.getAttributeType("FORGE_ZIP_FILE_INTERNAL_FILE_ATTRIBUTES"), moduleName, Utils.toBinString(internalFileAttributes)));
        attributes.add(new BlackboardAttribute(ingestAnalyzer.getAttributeType("FORGE_ZIP_FILE_EXTERNAL_FILE_ATTRIBUTES"), moduleName, Utils.toBinString(externalFileAttributes)));
        attributes.add(new BlackboardAttribute(ingestAnalyzer.getAttributeType("FORGE_ZIP_FILE_RELATIVE_OFFSET_OF_LOCAL_HEADER"), moduleName, relativeOffsetOfLocalHeader));
        attributes.add(new BlackboardAttribute(ingestAnalyzer.getAttributeType("FORGE_ZIP_FILE_EXTRA_FIELD"), moduleName, Utils.toHexString(extraField)));
        attributes.add(new BlackboardAttribute(ingestAnalyzer.getAttributeType("FORGE_ZIP_FILE_FILE_COMMENT"), moduleName, fileComment));
        attributes.add(new BlackboardAttribute(ingestAnalyzer.getAttributeType("FORGE_ZIP_FILE_ROOT_ID"), moduleName, rootFileTskID));
        attributes.add(new BlackboardAttribute(ingestAnalyzer.getAttributeType("FORGE_ZIP_FILE_ENCRYPTED"), moduleName, encrypted ? "true" : "false"));
        attributes.add(new BlackboardAttribute(ingestAnalyzer.getAttributeType("FORGE_ZIP_FILE_ENCRYPTION_METHOD"), moduleName, encryptionMethod));
        attributes.add(new BlackboardAttribute(ingestAnalyzer.getAttributeType("FORGE_ZIP_FILE_PATH"), moduleName, fileName));
        attributes.add(new BlackboardAttribute(ingestAnalyzer.getAttributeType("FORGE_ZIP_FILE_TYPE"), moduleName, directory ? "Directory" : "File"));
        return attributes;
    }

    /**
     * Edits a derived file in the ZIP central directory record. Have to stay as directory even for files. Otherwise autopsy will try to read data before decrypting and fail
     * sinc no data exist before.
     *
     * @param rootFile The root file associated with the ZIP archive.
     * @throws NoCurrentCaseException If there is no current case available.
     * @throws TskCoreException If an error occurs while updating the derived file.
     */
    public void editDerivedFile(ZipRootFile rootFile) throws NoCurrentCaseException, TskCoreException
    {
        FileManager fileManager;

        fileManager = Case.getCurrentCaseThrows().getServices().getFileManager();
        fileManager.updateDerivedFile((DerivedFile) abstractFile, abstractFile.getLocalPath(), uncompressedSize, getModifiedTime(), abstractFile.getCrtime(), abstractFile.getAtime(), getModifiedTime(), abstractFile.isFile(), abstractFile.getMIMEType(), "", "", "", "", EncodingType.NONE);

    }

    /**
     * Retrieves the last modified time of the file represented by this record. The method combines the DOS date and time fields, converts them into a human-readable datetime
     * string, and then converts that string into an epoch timestamp.
     *
     * @return The epoch timestamp representing the last modified time of the file.
     */
    private long getModifiedTime()
    {
        String datetime = Utils.convertDosDate(lastModFileDate) + " " + Utils.convertDosTime(lastModFileTime);
        return TimeUtilities.timeToEpoch(datetime);
    }

    /**
     * Retrieves the version information as a formatted string. The version is represented in the format "major.minor", where: - The major version is extracted from the
     * higher byte of the `versionMadeBy` field. - The minor version is extracted from the lower byte of the `versionMadeBy` field.
     *
     * @return A string representing the version in the format "XX.XX".
     */
    private String getVersionString()
    {
        return String.format("%02d.%02d", (versionMadeBy >> 8) & 0xFF, versionMadeBy & 0xFF);
    }
}
