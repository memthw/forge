package me.mthw.forge.ingest.analyzer.file;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.PDEncryption;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSDocument;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.cos.COSObjectKey;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.Volume;

import me.mthw.forge.Attribute;
import me.mthw.forge.ingest.ForgeIngestFactory;
import me.mthw.forge.ingest.analyzer.Analyzer;
import me.mthw.forge.utils.Utils;

/**
 * The FileAnalyzerPDF class is responsible for analyzing PDF files to determine their encryption properties and extract relevant metadata. It extends the Analyzer class
 * and provides functionality to process encrypted PDF files, retrieve encryption details, and create artifacts with extracted attributes.
 *
 *
 * Exceptions: - IllegalArgumentException: Thrown if the provided file is invalid. - IOException: Thrown if an error occurs while reading the file or processing the PDF.
 * - TskCoreException: Thrown if an error occurs during processing within the TSK framework. - BlackboardException: Thrown if an error occurs while adding attributes to
 * the blackboard.
 *
 * Attributes: - FORGE_PDF_FILTER: The filter used in the PDF. - FORGE_PDF_SUBFILTER: The subfilter used in the PDF. - FORGE_PDF_VERSION: The version of the PDF (V). -
 * FORGE_PDF_LENGTH: The length of the PDF. - FORGE_PDF_REVISION: The revision of the PDF (R). - FORGE_PDF_OWNER_KEY: The owner key of the PDF. - FORGE_PDF_USER_KEY: The
 * user key of the PDF. - FORGE_PDF_OWNER_ENCRYPTION_KEY: The owner encryption key of the PDF. - FORGE_PDF_USER_ENCRYPTION_KEY: The user encryption key of the PDF. -
 * FORGE_PDF_PERMISSIONS: The permissions (P) of the PDF. - FORGE_PDF_PERMS: The permissions (perms) of the PDF. - FORGE_PDF_CRYPT_FILTER_METHOD: The crypt filter method
 * used in the PDF. - FORGE_PDF_IS_METADATAENCRYPTED: Indicates if the metadata is encrypted. - FORGE_PDF_ID: The document ID of the PDF.
 *
 */
public class FileAnalyzerPDF extends Analyzer
{
    public FileAnalyzerPDF(BlackboardAttribute.Type mainAttribute, Blackboard blackboard, IngestJobContext context) throws BlackboardException
    {
        super(mainAttribute, blackboard, context);
    }

    /**
     * Processes a given file to analyze its encryption properties and extract relevant metadata if the file is an encrypted PDF.
     *
     * @param file The file to be processed, represented as an AbstractFile object.
     * @return true if the file is an encrypted PDF and metadata was successfully extracted, false otherwise.
     * @throws IllegalArgumentException If the provided file is invalid.
     * @throws IOException If an error occurs while reading the file.
     * @throws TskCoreException If an error occurs during processing within the TSK framework.
     * @throws BlackboardException If an error occurs while adding attributes to the blackboard.
     */
    @Override
    public boolean process(AbstractFile file) throws IllegalArgumentException, IOException, TskCoreException, BlackboardException
    {
        byte[] buffer = new byte[(int) file.getSize()];

        if (file.read(buffer, 0, (int) file.getSize()) != file.getSize())
            throw new IOException("Error reading file: " + file.getName());

        boolean isEncrypted = false;
        // Check if file is encrypted with catching InvalidPasswordException
        try
        {
            Loader.loadPDF(buffer);
        }
        catch (InvalidPasswordException ex)
        {
            isEncrypted = true;
        }
        if (isEncrypted == false)
            return false;

        COSDictionary encDict = null;

        encDict = getEncryptionDictionary(buffer);

        // Get and remove the document ID from the encryption dictionary
        COSString docIDString = (COSString) encDict.getItem("ID");
        encDict.setItem("ID", null);
        byte[] docID = docIDString.getBytes();

        // Create the encryption object
        PDEncryption enc = new PDEncryption(encDict);

        List<BlackboardAttribute> attributes = new ArrayList<BlackboardAttribute>();

        // Encryption Dictionary
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_PDF_FILTER"), moduleName, enc.getFilter()));
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_PDF_SUBFILTER"), moduleName, enc.getSubFilter()));
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_PDF_VERSION"), moduleName, enc.getVersion()));
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_PDF_LENGTH"), moduleName, enc.getLength()));

        // StandardSecurityHandler
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_PDF_REVISION"), moduleName, enc.getRevision()));
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_PDF_OWNER_KEY"), moduleName, Utils.toHexString(enc.getOwnerKey())));
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_PDF_USER_KEY"), moduleName, Utils.toHexString(enc.getUserKey())));
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_PDF_OWNER_ENCRYPTION_KEY"), moduleName, Utils.toHexString(enc.getOwnerEncryptionKey())));
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_PDF_USER_ENCRYPTION_KEY"), moduleName, Utils.toHexString(enc.getUserEncryptionKey())));
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_PDF_PERMISSIONS"), moduleName, Utils.toBinString(enc.getPermissions())));
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_PDF_PERMS"), moduleName, Utils.toHexString(enc.getPerms())));
        if (enc.getStdCryptFilterDictionary() != null && enc.getStdCryptFilterDictionary().getCryptFilterMethod() != null)
            attributes.add(new BlackboardAttribute(getAttributeType("FORGE_PDF_CRYPT_FILTER_METHOD"), moduleName, enc.getStdCryptFilterDictionary().getCryptFilterMethod().getName()));
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_PDF_IS_METADATAENCRYPTED"), moduleName, enc.isEncryptMetaData() ? 1 : 0));
        attributes.add(new BlackboardAttribute(getAttributeType("FORGE_PDF_ID"), moduleName, Utils.toHexString(docID)));

        ForgeIngestFactory.addMainFlag(file, mainAttribute);
        addArtifact(file, attributes, "Encrypted PDF", "Encrypted PDF file found");

        return true;

    }

    /**
     * Extracts the encryption dictionary from a PDF file represented as a byte array. This method identifies the encryption object in the PDF, removes encryption-related
     * keywords to allow parsing without a password, and retrieves the encryption dictionary.
     * 
     * @param bytes The byte array representation of the PDF file.
     * @return The encryption dictionary (COSDictionary) extracted from the PDF.
     * @throws IOException If an error occurs while processing the PDF.
     */
    private COSDictionary getEncryptionDictionary(byte[] bytes) throws IOException
    {
        // Find all /Encrypt keywords in pdf file
        String pdfString = new String(bytes);
        Pattern pattern = Pattern.compile("/Encrypt (\\d+) (\\d+) R");
        Matcher matcher = pattern.matcher(pdfString);

        int objNum = 0;
        int genNum = 0;
        // Get encryption object number and generation number. Does not matter which one, all should be same per specification
        while (matcher.find())
        {
            objNum = Integer.parseInt(matcher.group(1));
            genNum = Integer.parseInt(matcher.group(2));
        }

        // Remove all /Encrypt keywords from pdf file for pdf box to parse it without correct password
        pdfString = matcher.replaceAll("");

        bytes = pdfString.getBytes();

        PDDocument document = Loader.loadPDF(bytes);
        COSDocument cosDoc = document.getDocument();
        COSObject cosObj = cosDoc.getObjectFromPool(new COSObjectKey(objNum, genNum));
        // Get the encryption dictionary by using the saved object number and generation number
        COSDictionary dict = (COSDictionary) cosObj.getObject();

        // Add the document ID to the encryption dictionary
        COSArray arr = cosDoc.getDocumentID();
        COSBase documentID = arr.getObject(0);
        dict.setItem("ID", documentID);

        document.close();
        return dict;
    }

    /**
     * Creates an artifact with the specified type and description. This method is overridden to define the creation of a "FORGE_PDF" artifact with the description "FORGE
     * PDF".
     *
     * @throws BlackboardException if an error occurs during artifact creation.
     */
    @Override
    protected void createArtifact() throws BlackboardException
    {
        createArtifact("FORGE_PDF", "FORGE PDF");

    }

    /**
     * Initializes and populates the attributesMap with various attributes related to PDF analysis. Each attribute is defined with a unique key, a type, and a description.
     * These attributes represent metadata and properties of a PDF document, such as encryption details, permissions, version, and identifiers.
     *
     * Attributes added: - FORGE_PDF_FILTER: The filter used in the PDF. - FORGE_PDF_SUBFILTER: The subfilter used in the PDF. - FORGE_PDF_VERSION: The version of the PDF
     * (V). - FORGE_PDF_LENGTH: The length of the PDF. - FORGE_PDF_REVISION: The revision of the PDF (R). - FORGE_PDF_OWNER_KEY: The owner key of the PDF. -
     * FORGE_PDF_USER_KEY: The user key of the PDF. - FORGE_PDF_OWNER_ENCRYPTION_KEY: The owner encryption key of the PDF. - FORGE_PDF_USER_ENCRYPTION_KEY: The user
     * encryption key of the PDF. - FORGE_PDF_PERMISSIONS: The permissions (P) of the PDF. - FORGE_PDF_PERMS: The permissions (perms) of the PDF. -
     * FORGE_PDF_CRYPT_FILTER_METHOD: The crypt filter method used in the PDF. - FORGE_PDF_IS_METADATAENCRYPTED: Indicates if the metadata is encrypted. - FORGE_PDF_ID: The
     * document ID of the PDF.
     */
    @Override
    protected void createAttributes()
    {
        attributesMap.put("FORGE_PDF_FILTER", new Attribute("FORGE_PDF_FILTER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Filter"));
        attributesMap.put("FORGE_PDF_SUBFILTER", new Attribute("FORGE_PDF_SUBFILTER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SubFilter"));
        attributesMap.put("FORGE_PDF_VERSION", new Attribute("FORGE_PDF_VERSION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER, "Version (V)"));
        attributesMap.put("FORGE_PDF_LENGTH", new Attribute("FORGE_PDF_LENGTH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER, "Length"));
        attributesMap.put("FORGE_PDF_REVISION", new Attribute("FORGE_PDF_REVISION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER, "Revision (R)"));
        attributesMap.put("FORGE_PDF_OWNER_KEY", new Attribute("FORGE_PDF_OWNER_KEY", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Owner Key"));
        attributesMap.put("FORGE_PDF_USER_KEY", new Attribute("FORGE_PDF_USER_KEY", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "User Key"));
        attributesMap.put("FORGE_PDF_OWNER_ENCRYPTION_KEY", new Attribute("FORGE_PDF_OWNER_ENCRYPTION_KEY", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Owner Encryption Key"));
        attributesMap.put("FORGE_PDF_USER_ENCRYPTION_KEY", new Attribute("FORGE_PDF_USER_ENCRYPTION_KEY", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "User Encryption Key"));
        attributesMap.put("FORGE_PDF_PERMISSIONS", new Attribute("FORGE_PDF_PERMISSIONS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Permissions (P)"));
        attributesMap.put("FORGE_PDF_PERMS", new Attribute("FORGE_PDF_PERMS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Permissions (perms)"));
        attributesMap.put("FORGE_PDF_CRYPT_FILTER_METHOD", new Attribute("FORGE_PDF_CRYPT_FILTER_METHOD", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Crypt Filter Method"));
        attributesMap.put("FORGE_PDF_IS_METADATAENCRYPTED", new Attribute("FORGE_PDF_IS_METADATAENCRYPTED", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER, "Metadata Encrypted"));
        attributesMap.put("FORGE_PDF_ID", new Attribute("FORGE_PDF_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Document ID"));
    }

    /**
     * Processes the given Volume object. This method is not supported for the Volume content type and will always throw an UnsupportedOperationException.
     *
     * @param volume The Volume object to be processed.
     * @throws UnsupportedOperationException if this method is called, as processing of content type Volume is not supported
     */
    @Override
    public boolean process(Volume volume)
    {
        throw new UnsupportedOperationException("Content type Volume not supported on file analyzer");
    }

}