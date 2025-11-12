package me.mthw.forge.ingest.analyzer.file;

import me.mthw.forge.Attribute;
import me.mthw.forge.ingest.ForgeIngestFactory;
import me.mthw.forge.ingest.ZIP.ZipCentralDirectoryRecord;
import me.mthw.forge.ingest.ZIP.ZipRootFile;
import me.mthw.forge.ingest.analyzer.Analyzer;
import me.mthw.forge.utils.Utils;

import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardAttribute;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.sleuthkit.datamodel.ReadContentInputStream;
import org.sleuthkit.datamodel.ReadContentInputStream.ReadContentInputStreamException;

import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.Volume;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.ingest.IngestJobContext;

/**
 * The FileAnalyzerZIPArchive class is responsible for analyzing ZIP archive files within the context of a forensic investigation. It extends the Analyzer class and
 * provides functionality to process ZIP archives, extract metadata, and identify encrypted files within the archive. The class also supports creating artifacts and
 * attributes for the analyzed ZIP files. Limitations: - Does not support split ZIP archives or ZIP64 format.
 *
 *
 * Exceptions: - Throws various exceptions such as IllegalAccessError, TskCoreException, IOException, and BlackboardException for error handling during processing.
 */
public class FileAnalyzerZIPArchive extends Analyzer
{
    FileAnalyzerZIPFile zipFileIngestAnalyzer;
    FileManager fileManager;

    public FileAnalyzerZIPArchive(BlackboardAttribute.Type mainAttribute, Blackboard blackboard, IngestJobContext context) throws BlackboardException, NoCurrentCaseException
    {
        super(mainAttribute, blackboard, context);
        this.zipFileIngestAnalyzer = new FileAnalyzerZIPFile(mainAttribute, blackboard, context);
        this.fileManager = Case.getCurrentCaseThrows().getServices().getFileManager();
    }

    /**
     * Processes a given ZIP archive file and extracts relevant metadata and attributes. If the ZIP archive is encrypted, it adds specific attributes and artifacts to the
     * analysis.
     *
     * @param file The abstract file representing the ZIP archive to be processed.
     * @return true if the ZIP archive is encrypted and processed successfully, false otherwise.
     * @throws IllegalAccessError If there is an illegal access error during processing.
     * @throws TskCoreException If there is an error with the Sleuth Kit core.
     * @throws IOException If an I/O error occurs while reading the file.
     * @throws BlackboardException If there is an error adding attributes to the blackboard.
     * @throws NoCurrentCaseException If there is no current case open during processing.
     */
    @Override
    public boolean process(AbstractFile file) throws IllegalAccessError, TskCoreException, IOException, BlackboardException, NoCurrentCaseException
    {
        ReadContentInputStream inStream = new ReadContentInputStream(file);
        ZipRootFile rootFile = new ZipRootFile();
        rootFile.abstractFile = file;
        findAndParseEOCDHeader(inStream, rootFile);

        rootFile.filePath = file.getParentPath() + file.getName();
        rootFile.tskID = file.getId();

        parseCDHeader(inStream, rootFile);

        inStream.close();

        if (rootFile.encrypted == false)
            return false;

        // Main forge flag
        ForgeIngestFactory.addMainFlag(rootFile.abstractFile, mainAttribute);

        List<BlackboardAttribute> attributes = new ArrayList<BlackboardAttribute>();
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_ZIP_ARCHIVE_ENC_METHOD"), moduleName, rootFile.encryptionMethod));
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_ZIP_ARCHIVE_COMMENT"), moduleName, rootFile.comment));
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_ZIP_ARCHIVE_CDRECORDS"), moduleName, rootFile.cdRecords));
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_ZIP_ARCHIVE_CDOFFSET"), moduleName, rootFile.cdOffset));
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_ZIP_ARCHIVE_EOCDOFFSET"), moduleName, rootFile.eocdOffset));

        addArtifact(rootFile.abstractFile, attributes, "Encrypted Zip Archive", "Encrypted Zip archive found");
        for (ZipCentralDirectoryRecord record : rootFile.records)
        {
            attributes = record.getAttributes(zipFileIngestAnalyzer, moduleName);
            ForgeIngestFactory.addMainFlag(record.abstractFile, mainAttribute);
            zipFileIngestAnalyzer.addArtifact(record.abstractFile, attributes, "Encrypted Zip File", "Encrypted File archive found");
            record.editDerivedFile(rootFile);
        }

        return true;
    }

    /**
     * Finds and parses the End of Central Directory (EOCD) header in a ZIP archive. This method locates the EOCD header by scanning backward from the end of the file and
     * extracts relevant metadata from it. It also validates that the ZIP archive is not a split or Zip64 archive, as these are not supported.
     *
     * @param inStream The input stream to read the ZIP archive content.
     * @param rootFile The root file object to store extracted metadata such as comment, central directory records, and offsets.
     * @throws IllegalAccessError If the EOCD header cannot be found.
     * @throws ReadContentInputStreamException If an error occurs while reading the input stream.
     * @throws UnsupportedOperationException If the ZIP archive is a split archive or uses Zip64 format.
     */
    private void findAndParseEOCDHeader(ReadContentInputStream inStream, ZipRootFile rootFile) throws IllegalAccessError, ReadContentInputStreamException, UnsupportedOperationException
    {
        byte[] eocdHeader = new byte[] { 0x50, 0x4B, 0x05, 0x06 };
        byte[] buffer = new byte[4];

        long offset = inStream.getLength() - 22;

        inStream.seek(offset);
        inStream.read(buffer, 0, 4);

        while (Arrays.equals(eocdHeader, buffer) == false)
        {
            if (offset <= 0)
                throw new IllegalAccessError("EOCD header not found");

            offset--;
            inStream.seek(offset);
            inStream.read(buffer, 0, 4);
        }

        inStream.seek(offset + 4);

        short diskNumber = 0;
        short diskNumberWithCD = 0;
        short cdRecordsOnDisk = 0;
        short cdRecords = 0;
        int cdSize = 0;
        long cdOffset = 0;
        short commentLength = 0;

        diskNumber = Utils.readShort(inStream);
        diskNumberWithCD = Utils.readShort(inStream);
        cdRecordsOnDisk = Utils.readShort(inStream);
        cdRecords = Utils.readShort(inStream);
        cdSize = Utils.readInt(inStream);
        cdOffset = Utils.readInt(inStream);
        commentLength = Utils.readShort(inStream);

        if (cdRecordsOnDisk != cdRecords)
            throw new UnsupportedOperationException("Split zip file is not supported");

        if (diskNumber == 0xffff || diskNumberWithCD == 0xfff || cdRecordsOnDisk == 0xffff || cdRecords == 0xffff || cdSize == 0xffffffff || cdOffset == 0xffffffff)
            throw new UnsupportedOperationException("Zip64 is not supported");

        byte[] commentByte = new byte[commentLength];

        inStream.read(commentByte, 0, commentLength);

        rootFile.comment = new String(commentByte);
        rootFile.cdRecords = cdRecords;
        rootFile.cdOffset = cdOffset;
        rootFile.eocdOffset = offset;

    }

    /**
     * Parses the Central Directory (CD) header of a ZIP archive and extracts metadata for each file or directory entry in the archive. This method reads the CD header
     * records and populates the provided ZipRootFile object with the extracted information.
     *
     * @param inStream The input stream to read the ZIP archive content.
     * @param rootFile The root file object representing the ZIP archive, which will be populated with metadata about its entries.
     * @throws IllegalAccessError If the CD header signature is not found.
     * @throws ReadContentInputStreamException If an error occurs while reading from the input stream.
     * @throws TskCoreException If an error occurs while interacting with the file manager.
     */
    private void parseCDHeader(ReadContentInputStream inStream, ZipRootFile rootFile) throws IllegalAccessError, ReadContentInputStreamException, TskCoreException
    {
        inStream.seek(rootFile.cdOffset);
        for (int i = 0; i < rootFile.cdRecords; i++)
        {

            if (Utils.readInt(inStream) != 0x02014b50)
                throw new IllegalAccessError("CD header not found");

            ZipCentralDirectoryRecord record = new ZipCentralDirectoryRecord();
            short compressionMethodShort = 0;

            record.versionMadeBy = Utils.readShort(inStream);
            record.versionNeededToExtract = Utils.readShort(inStream);
            record.generalPurposeBitFlag = Utils.readShort(inStream);
            compressionMethodShort = Utils.readShort(inStream);
            record.lastModFileTime = Utils.readShort(inStream);
            record.lastModFileDate = Utils.readShort(inStream);
            record.crc32 = Utils.readInt(inStream);
            record.compressedSize = Utils.readInt(inStream);
            record.uncompressedSize = Utils.readInt(inStream);
            record.fileNameLength = Utils.readShort(inStream);
            record.extraFieldLength = Utils.readShort(inStream);
            record.fileCommentLength = Utils.readShort(inStream);
            record.diskNumberStart = Utils.readShort(inStream);
            record.internalFileAttributes = Utils.readShort(inStream);
            record.externalFileAttributes = Utils.readInt(inStream);
            record.relativeOffsetOfLocalHeader = Utils.readInt(inStream);
            record.rootFileTskID = rootFile.tskID;

            // Check if the file is encrypted
            if ((record.generalPurposeBitFlag & 1) == 0x01)
            {
                rootFile.encrypted = true;
                record.encrypted = true;
            }

            // Check if the file is encrypted with ZipCrypto
            if (record.encrypted && (compressionMethodShort != 99) && (record.generalPurposeBitFlag & 0x40) == 0)
            {
                rootFile.encryptionMethod = "ZipCrypto";
                record.encryptionMethod = "ZipCrypto";
            }

            // Check if the file is encrypted with proprietary strong encryption
            if (record.encrypted && (record.generalPurposeBitFlag & 0x40) == 0x40)
            {
                rootFile.encryptionMethod = "Strong Encryption";
                record.encryptionMethod = "Strong Encryption";
            }

            byte[] fileNameByte = new byte[record.fileNameLength];
            byte[] extraFieldByte = new byte[record.extraFieldLength];
            byte[] fileCommentByte = new byte[record.fileCommentLength];

            inStream.read(fileNameByte, 0, record.fileNameLength);
            inStream.read(extraFieldByte, 0, record.extraFieldLength);
            inStream.read(fileCommentByte, 0, record.fileCommentLength);


            // Check if the file is encrypted with AES and get the actual compression method
            if (record.encrypted && (compressionMethodShort == 99) && (record.generalPurposeBitFlag & 0x40) == 0)
            {
                int extraFieldOffset = 0;
                while (extraFieldOffset < extraFieldByte.length)
                {
                    short header = Utils.readShort(extraFieldByte, extraFieldOffset);
                    if (header != -26367)
                    {
                        extraFieldOffset += 4+Utils.readShort(extraFieldByte, extraFieldOffset + 2);
                        continue;
                    }
                    // Is not used but keeping it for future features
                    // short size = utils.readShort(extraFieldByte, 2);
                    // short vendorVersion = utils.readShort(extraFieldByte, 4);
                    // short vendorID = utils.readShort(extraFieldByte, 6);
                    byte aesKeyLength = extraFieldByte[8];
                    short compressionMethod = Utils.readShort(extraFieldByte, extraFieldOffset + 9);

                    switch (aesKeyLength)
                    {
                    case 0x01:
                        rootFile.encryptionMethod = "AES-128";
                        record.encryptionMethod = "AES-128";
                        break;
                    case 0x02:
                        rootFile.encryptionMethod = "AES-192";
                        record.encryptionMethod = "AES-192";
                        break;
                    case 0x03:
                        rootFile.encryptionMethod = "AES-256";
                        record.encryptionMethod = "AES-256";
                        break;
                    default:

                        rootFile.encryptionMethod = "Unknown";
                        record.encryptionMethod = "Unknown";
                        break;
                    }

                    compressionMethodShort = compressionMethod;
                    break;
                }  
            }

            if (record.encrypted && record.encryptionMethod.isEmpty() )
            {
                rootFile.encryptionMethod = "Unknown";
                record.encryptionMethod = "Unknown";
            }

            record.compressionMethod = getCompressionMethodString(compressionMethodShort);
            rootFile.compressionMethod = getCompressionMethodString(compressionMethodShort);

            if (compressionMethodShort == 0)
            {
                rootFile.compressed = false;
                record.compressed = false;
            }
            else
            {
                rootFile.compressed = true;
                record.compressed = true;
            }

            record.fileName = "/" + new String(fileNameByte);
            String[] splitted = record.fileName.split("/");
            record.name = splitted[splitted.length - 1];
            if (record.fileName.endsWith("/"))
            {
                record.directory = true;
                record.name += "/";
            }

            record.extraField = extraFieldByte;
            record.fileComment = new String(fileCommentByte);

            String str = rootFile.filePath + record.fileName.substring(0, record.fileName.length() - record.name.length() - 1);
            String name = record.name.endsWith("/") ? record.name.substring(0, record.name.length() - 1) : record.name;
            List<AbstractFile> abstractFiles = fileManager.findFiles(name, str);
            record.abstractFile = abstractFiles.get(0);

            rootFile.records.add(record);
        }
    }

    /**
     * Returns a string representation of the compression method based on the provided compression method code. The string includes the name of the compression method and the
     * corresponding code in parentheses.
     *
     * @param compressionMethod The short value representing the compression method code.
     * @return A string describing the compression method. If the code is not recognized, it returns the code in parentheses.
     */
    private String getCompressionMethodString(short compressionMethod)
    {
        switch (compressionMethod)
        {
        case 0:
            return "Stored (" + compressionMethod + ")";
        case 1:
            return "Shrunk (" + compressionMethod + ")";
        case 2:
            return "Reduced with compression factor 1 (" + compressionMethod + ")";
        case 3:
            return "Reduced with compression factor 2 (" + compressionMethod + ")";
        case 4:
            return "Reduced with compression factor 3 (" + compressionMethod + ")";
        case 5:
            return "Reduced with compression factor 4 (" + compressionMethod + ")";
        case 6:
            return "Imploded (" + compressionMethod + ")";
        case 7:
            return "Tokenized (" + compressionMethod + ")";
        case 8:
            return "Deflated (" + compressionMethod + ")";
        case 9:
            return "Deflated64 (" + compressionMethod + ")";
        case 10:
            return "PKWARE DCL Imploded (" + compressionMethod + ")";
        case 12:
            return "BZIP2 (" + compressionMethod + ")";
        case 14:
            return "LZMA (" + compressionMethod + ")";
        case 16:
            return "IBM z/OS CMPSC  (" + compressionMethod + ")";
        case 18:
            return "IBM TERSE (" + compressionMethod + ")";
        case 19:
            return "IBM LZ77 (" + compressionMethod + ")";
        case 93:
            return "zstd (" + compressionMethod + ")";
        case 94:
            return "MP3 (" + compressionMethod + ")";
        case 95:
            return "XZ (" + compressionMethod + ")";
        case 96:
            return "JPEG variant (" + compressionMethod + ")";
        case 97:
            return "WavPack (" + compressionMethod + ")";
        case 98:
            return "PPMd (" + compressionMethod + ")";
        case 99:
            return ""; // X-AE encryption
        default:
            return " (" + compressionMethod + ")";
        }
    }

    /**
     * Creates an artifact for a ZIP archive with a specified type and description. This method is overridden to define the specific artifact type and description for ZIP
     * archives in the context of the application.
     *
     * @throws BlackboardException if there is an error during artifact creation.
     */
    @Override
    protected void createArtifact() throws BlackboardException
    {
        createArtifact("FORGE_ZIP", "FORGE ZIP Archive");
    }

    /**
     * Initializes and populates the attributes map with metadata attributes related to ZIP archive analysis. Each attribute represents a specific property of the ZIP
     * archive, such as encryption method, compression method, or structural details like central directory records and offsets.
     *
     * Attributes added: - FORGE_ZIP_ARCHIVE_ENC_METHOD: The encryption method used in the ZIP archive. - FORGE_ZIP_ARCHIVE_COMP_METHOD: The compression method used in the
     * ZIP archive. - FORGE_ZIP_ARCHIVE_COMMENT: The comment associated with the ZIP archive. - FORGE_ZIP_ARCHIVE_CDRECORDS: The number of central directory records in the
     * ZIP archive. - FORGE_ZIP_ARCHIVE_CDOFFSET: The offset of the central directory in the ZIP archive. - FORGE_ZIP_ARCHIVE_EOCDOFFSET: The offset of the end of central
     * directory record in the ZIP archive.
     */
    @Override
    protected void createAttributes()
    {
        attributesMap.put("FORGE_ZIP_ARCHIVE_ENC_METHOD", new Attribute("FORGE_ZIP_ARCHIVE_ENC_METHOD", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Encryption Method"));
        attributesMap.put("FORGE_ZIP_ARCHIVE_COMP_METHOD", new Attribute("FORGE_ZIP_ARCHIVE_COMP_METHOD", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Compression Method"));
        attributesMap.put("FORGE_ZIP_ARCHIVE_COMMENT", new Attribute("FORGE_ZIP_ARCHIVE_COMMENT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Comment"));
        attributesMap.put("FORGE_ZIP_ARCHIVE_CDRECORDS", new Attribute("FORGE_ZIP_ARCHIVE_CDRECORDS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "CD Records"));
        attributesMap.put("FORGE_ZIP_ARCHIVE_CDOFFSET", new Attribute("FORGE_ZIP_ARCHIVE_CDOFFSET", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "CD Offset"));
        attributesMap.put("FORGE_ZIP_ARCHIVE_EOCDOFFSET", new Attribute("FORGE_ZIP_ARCHIVE_EOCDOFFSET", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "EOCD Offset"));
    }

    /**
     * Processes the given volume. This implementation does not support processing of content type Volume and will throw an UnsupportedOperationException.
     *
     * @param volume the volume to be processed
     * @return always throws an exception and does not return a value
     * @throws UnsupportedOperationException if this method is called, as processing of content type Volume is not supported
     */
    @Override
    public boolean process(Volume volume)
    {
        throw new UnsupportedOperationException("Content type Volume not supported on file analyzer");
    }

}