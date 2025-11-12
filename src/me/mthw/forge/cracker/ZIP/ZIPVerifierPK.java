package me.mthw.forge.cracker.ZIP;

import java.io.IOException;

import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.TskCoreException;

import me.mthw.forge.utils.Utils;

/**
 * The `ZIPVerifierPK` class extends the `ZIPVerifier` class and provides functionality for verifying passwords for ZIP files encrypted using the PKZIP encryption method.
 * It implements the decryption and verification logic based on the PKZIP specification.
 *
 * This class is responsible for: - Initializing encryption keys and CRC-32 tables. - Decrypting the ZIP file header using the provided password. - Verifying the password
 * by comparing decrypted data with a verification byte.
 *
 * The class uses a custom implementation of CRC-32 checksum calculation and decryption algorithms as described in the PKZIP appnote.
 *
 * Key features: - Initialization of CRC-32 table for efficient checksum computation. - Custom decryption logic for PKZIP-encrypted ZIP files. - Password verification by
 * comparing decrypted header data.
 *
 * Usage: ZIPVerifierPK verifier = new ZIPVerifierPK(artifact, blackboard, rootFile); boolean isPasswordValid = verifier.verifyPassword("password123");
 *
 * Note: ZipCrypto perfoms check only on one byte. Use of library to try extract the file helps, but still can have collisions.
 *
 * Based on section 6.0 of APPNOTE https://support.pkware.com/pkzip/appnote
 */
public class ZIPVerifierPK extends ZIPVerifier
{
    private byte[] header;
    private byte verificationByte;

    private int key0;
    private int key1;
    private int key2;

    // Lookup CRC-32 table for checksum calculation
    private final int[] CRC_TABLE = new int[256];

    /**
     * Constructs a ZIPVerifierPK object to verify ZIP file integrity.
     *
     * @param artifact The BlackboardArtifact object containing metadata and attributes related to the ZIP file.
     * @param blackboard The Blackboard object used to retrieve attribute types and associated data.
     * @param rootFile The AbstractFile object representing the root file of the ZIP archive.
     * @throws TskCoreException If there is an error accessing the SleuthKit core.
     * @throws IOException If there is an error reading the file or if the General Purpose Bit Flag is invalid.
     *
     * This constructor initializes the ZIPVerifierPK object by reading the ZIP file header and extracting necessary information for verification. It determines whether the
     * CRC value is stored in the data descriptor or directly in the file attributes. The verification byte is calculated based on the DOS time or CRC32 value, depending on
     * the ZIP file's general purpose bit flag. Additionally, it initializes the CRC table for further verification.
     */
    ZIPVerifierPK(BlackboardArtifact artifact, Blackboard blackboard, AbstractFile rootFile) throws TskCoreException, IOException
    {
        super(artifact, blackboard, rootFile);

        this.header = new byte[12];

        byte[] buffer = new byte[2];
        rootFile.read(buffer, localHeaderOffset + 26, 2);
        short fileNameLength = Utils.byteToShort(buffer);
        rootFile.read(buffer, localHeaderOffset + 28, 2);
        short extraFieldLength = Utils.byteToShort(buffer);

        rootFile.read(this.header, localHeaderOffset + extraFieldLength + fileNameLength + 30, 12);

        String generalPurposeBitFlag = artifact.getAttribute(blackboard.getAttributeType("FORGE_ZIP_FILE_GEN_PURP_FLAG")).getValueString();
        if (generalPurposeBitFlag.length() != 16)
            throw new IOException("Invalid General Purpose Bit Flag");

        boolean crcInDataDescriptor = (generalPurposeBitFlag.charAt(12) == '1') ? true : false;
        if (crcInDataDescriptor)
        {
            String time = artifact.getAttribute(blackboard.getAttributeType("FORGE_ZIP_FILE_LAST_MOD_TIME")).getValueString();

            short dosTime = Utils.convertDosTime(time);

            // Return the least significant byte (first byte)
            verificationByte = (byte) (dosTime >> 8 & 0xFF);
        }
        else
        {
            verificationByte = Utils.hexStringToByteArray(artifact.getAttribute(blackboard.getAttributeType("FORGE_ZIP_FILE_CRC32")).getValueString())[3];
        }

        initCRCTable();
    }

    /**
     * Verifies the provided password by decrypting a header and checking its validity.
     *
     * This method initializes encryption keys, updates them based on the password, and decrypts a predefined header. It then compares a specific byte in the decrypted header
     * with a verification byte to determine if the password is valid. If the initial check passes, it delegates further verification to an external library method.
     *
     * @param password The password to be verified.
     * @return {@code true} if the password is valid; {@code false} otherwise.
     */
    @Override
    public boolean verifyPassword(String password)
    {
        key0 = 0x12345678;
        key1 = 0x23456789;
        key2 = 0x34567890;
        for (char c : password.toCharArray())
        {
            updateKeys((byte) c);
        }
        byte[] decryptedHeader = decryptBytes(header);
        if (decryptedHeader[11] == verificationByte)
            return verifyPasswordLib(password);
        return false;
    }

    /**
     * Initializes the CRC (Cyclic Redundancy Check) table used for computing CRC-32 checksums. The table is precomputed with values based on the polynomial 0xEDB88320, which
     * is the standard polynomial used in CRC-32.
     * 
     * This method populates the `CRC_TABLE` array with 256 entries, where each entry corresponds to the CRC value for a single byte. The computation involves iterating
     * through all possible byte values (0-255) and applying bitwise operations to calculate the CRC value for each.
     * 
     * The resulting table is used to efficiently compute CRC-32 checksums for data streams by avoiding repeated recalculation of the polynomial for each byte.
     */
    private void initCRCTable()
    {
        for (int i = 0; i < 256; i++)
        {
            int r = i;
            for (int j = 0; j < 8; j++)
            {
                if ((r & 1) != 0)
                    r = (r >>> 1) ^ 0xEDB88320;
                else
                    r >>>= 1;
            }
            CRC_TABLE[i] = r;
        }
    }

    /**
     * Updates the internal encryption keys using the provided byte.
     * 
     * Function from appnote section 6.1.5
     * 
     * @param b The byte used to update the encryption keys.
     */
    private void updateKeys(byte b)
    {
        key0 = crc32(key0, b);
        key1 = ((key1 + (key0 & 0xFF)) * 134775813 + 1);
        key2 = crc32(key2, (byte) (key1 >>> 24));
    }

    /**
     * Computes the updated CRC-32 checksum value for a single byte of data.
     *
     * @param oldCrc The current CRC-32 checksum value.
     * @param b The next byte of data to include in the checksum calculation.
     * @return The updated CRC-32 checksum value after processing the given byte.
     */
    private int crc32(int oldCrc, byte b)
    {
        return (oldCrc >>> 8) ^ CRC_TABLE[(oldCrc ^ b) & 0xFF];
    }

    /**
     * Decrypts a single byte using a custom algorithm based on the internal state. The method performs bitwise operations and arithmetic on the `key2` field to produce the
     * decrypted byte. Function from appnote section 6.1.6
     *
     * @return The decrypted byte as a result of the computation.
     */
    private byte decryptByte()
    {
        int temp = key2 | 2;
        return (byte) ((temp * (temp ^ 1)) >>> 8);
    }

    /**
     * Decrypts a single byte using the current decryption state. Function from appnote section 6.1.7
     * 
     * @param c The byte to be decrypted.
     * @return The decrypted byte after applying the decryption algorithm and updating the keys.
     */
    private byte decryptByte(byte c)
    {
        byte temp = (byte) (c ^ decryptByte());
        updateKeys(temp);
        return temp;
    }

    /**
     * Decrypts an array of bytes by processing each byte individually. Function from appnote section 6.1.7
     *
     * @param input The array of bytes to be decrypted. Must not be null.
     * @return A new array of bytes where each byte has been decrypted.
     */
    private byte[] decryptBytes(byte[] input)
    {
        byte[] out = new byte[input.length];
        for (int i = 0; i < input.length; i++)
        {
            out[i] = decryptByte(input[i]);
        }
        return out;
    }

}
