package me.mthw.forge.ingest.ZIP;

import java.util.ArrayList;
import java.util.List;

import org.sleuthkit.datamodel.AbstractFile;

/**
 * Represents the root file of a ZIP archive, containing metadata and records related to the ZIP file's structure and contents. Fields are based on the names from the
 * APPNOTE specification.
 */
public class ZipRootFile
{
    public String comment;
    public long cdRecords;
    public long cdOffset;
    public long eocdOffset;

    public String compressionMethod;
    public boolean encrypted;
    public String encryptionMethod = new String();
    public boolean compressed;

    public String filePath;
    public AbstractFile abstractFile;
    public long tskID;
    public List<ZipCentralDirectoryRecord> records = new ArrayList<>(); // list of files in the zip (all on the same level)

}
