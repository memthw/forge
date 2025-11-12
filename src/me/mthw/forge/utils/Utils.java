package me.mthw.forge.utils;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.sleuthkit.autopsy.coreutils.StringExtract;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.ReadContentInputStream;
import org.sleuthkit.datamodel.ReadContentInputStream.ReadContentInputStreamException;
import org.sleuthkit.datamodel.TskCoreException;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.apache.poi.xssf.extractor.XSSFExcelExtractor;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.apache.poi.xwpf.extractor.XWPFWordExtractor;
import org.apache.poi.xwpf.usermodel.XWPFDocument;

public class Utils
{
    public static String toHexString(byte[] bytes)
    {
        if (bytes == null || bytes.length == 0)
            return null;
        StringBuilder sb = new StringBuilder("0x");
        for (byte b : bytes)
        {
            sb.append(String.format("%02x", b)); // format as 2-digit lowercase hex
        }
        return sb.toString();
    }

    public static String toHexString(int number)
    {
        return String.format("0x%08x", number);
    }

    public static String toBinString(int number)
    {
        return String.format("%32s", Integer.toBinaryString(number)).replace(' ', '0');
    }

    public static String toBinString(short number)
    {
        return String.format("%16s", Integer.toBinaryString((short) number)).replace(' ', '0');
    }

    /**
     * Converts a hexadecimal string to a byte array.
     *
     * This method takes a string representation of hexadecimal values and converts it into a corresponding byte array. The input string may optionally start with "0x" or
     * "0X", which will be ignored during the conversion. Each pair of hexadecimal digits in the string is converted into a single byte.
     *
     * @param byteString The hexadecimal string to be converted. It may optionally start with "0x" or "0X". If the string is null or empty, the method returns {@code null}.
     * @return A byte array representing the hexadecimal values in the input string, or {@code null} if the input string is null or empty.
     * @throws NumberFormatException If the input string contains invalid hexadecimal characters or if its length is not even.
     */
    public static byte[] hexStringToByteArray(String byteString)
    {

        // Perofrms a null check and empty string check
        if (byteString == null || byteString.isEmpty())
            return null;

        // Checks if the string starts with 0x or 0X and removes it
        if (byteString.startsWith("0x") || byteString.startsWith("0X"))
            byteString = byteString.substring(2);

        int length = byteString.length();
        byte[] bytes = new byte[length / 2];

        // Iterates through the string two characters at a time, converting each pair of hex digits to a byte
        for (int i = 0; i < length; i += 2)
            bytes[i / 2] = (byte) Integer.parseInt(byteString.substring(i, i + 2), 16);

        return bytes;
    }

    /**
     * Converts a binary string representation into a byte array. 32-bit to unsigned number least significant byte first
     * 
     * This method takes a string of binary digits (e.g., "0b11001010" or "11001010") and converts it into a corresponding byte array. The binary string can optionally start
     * with "0b" or "0B", which will be ignored during conversion.
     *
     * @param bitString The binary string to convert. It can optionally start with "0b" or "0B". Must have a length that is a multiple of 8 (excluding the "0b" prefix). If
     * the string is null or empty, the method returns {@code null}.
     * @return A byte array representing the binary string, or {@code null} if the input string is null or empty.
     * @throws NumberFormatException If the binary string contains invalid characters or its length is not a multiple of 8.
     */
    public static byte[] binaryStringToByteArray(String bitString)
    {
        // Performs a null check and empty string check
        if (bitString == null || bitString.isEmpty())
            return null;

        // Checks if the string starts with 0b or 0B and removes it
        if (bitString.startsWith("0b") || bitString.startsWith("0B"))
            bitString = bitString.substring(2);

        int length = bitString.length();
        byte[] bytes = new byte[length / 8];
        // Iterates through the string eight characters at a time, converting each byte
        for (int i = 0; i < length; i += 8)
            bytes[bytes.length - 1 - (i / 8)] = (byte) Integer.parseInt(bitString.substring(i, i + 8), 2);

        return bytes;
    }

    public static short byteToShort(byte[] buffer)
    {
        return (short) ((buffer[1] << 8) | (buffer[0] & 0xFF));
    }

    public static short convertDosTime(String time)
    {
        String[] parts = time.split(":");
        short hour = Short.parseShort(parts[0]);
        short min = Short.parseShort(parts[1]);
        short sec = Short.parseShort(parts[2]);

        short dosSec = (short) (sec / 2);

        return (short) ((hour << 11) | (min << 5) | dosSec);
    }

    public static String convertDosTime(short time)
    {
        short sec = (short) ((time & 0x1F) * 2);
        short min = (short) ((time >> 5) & 0x3F);
        short hour = (short) ((time >> 11) & 0x1F);
        return String.format("%02d:%02d:%02d", hour, min, sec);
    }

    public static short convertDosDate(String date)
    {
        String[] parts = date.split(":");
        short year = Short.parseShort(parts[0]);
        short month = Short.parseShort(parts[1]);
        short day = Short.parseShort(parts[2]);

        short dosYear = (short) (year - 1980);

        return (short) ((dosYear << 9) | (month << 5) | day);
    }

    public static String convertDosDate(short date)
    {
        short day = (short) (date & 0x1F);
        short month = (short) ((date >> 5) & 0xF);
        short year = (short) (((date >> 9) & 0x7F) + 1980);
        return String.format("%04d-%02d-%02d", year, month, day);
    }

    public static short readShort(ReadContentInputStream inStream) throws ReadContentInputStreamException
    {
        byte[] bufferShort = new byte[2];
        inStream.read(bufferShort, 0, 2);

        return (short) ((bufferShort[1] << 8) | (bufferShort[0] & 0xFF));
    }

    public static short readShort(byte[] buffer, int offset)
    {
        return (short) ((buffer[offset + 1] << 8) | (buffer[offset] & 0xFF));
    }

    public static short readShortBE(byte[] buffer, int offset)
    {
        return (short) ((buffer[offset] << 8) | (buffer[offset + 1] & 0xFF));
    }

    public static int readInt(ReadContentInputStream inStream) throws ReadContentInputStreamException
    {
        byte[] bufferInt = new byte[4];
        inStream.read(bufferInt, 0, 4);

        return (bufferInt[3] << 24) | ((bufferInt[2] & 0xFF) << 16) | ((bufferInt[1] & 0xFF) << 8) | (bufferInt[0] & 0xFF);
    }

    public static int readInt(byte[] buffer, int offset)
    {
        return (buffer[offset + 3] << 24) | ((buffer[offset + 2] & 0xFF) << 16) | ((buffer[offset + 1] & 0xFF) << 8) | (buffer[offset] & 0xFF);
    }

    public static int readIntBE(byte[] buffer, int offset)
    {
        return (buffer[offset] << 24) | ((buffer[offset + 1] & 0xFF) << 16) | ((buffer[offset + 2] & 0xFF) << 8) | (buffer[offset + 3] & 0xFF);
    }

    public static long readLong(byte[] buffer, int offset)
    {
        return ((long) buffer[offset + 7] << 56) | ((long) (buffer[offset + 6] & 0xFF) << 48) | ((long) (buffer[offset + 5] & 0xFF) << 40) | ((long) (buffer[offset + 4] & 0xFF) << 32) | ((long) (buffer[offset + 3] & 0xFF) << 24) | ((long) (buffer[offset + 2] & 0xFF) << 16) | ((long) (buffer[offset + 1] & 0xFF) << 8) | (buffer[offset] & 0xFF);
    }

    public static long readLongBE(byte[] buffer, int offset)
    {
        return ((long) buffer[offset] << 56) | ((long) (buffer[offset + 1] & 0xFF) << 48) | ((long) (buffer[offset + 2] & 0xFF) << 40) | ((long) (buffer[offset + 3] & 0xFF) << 32) | ((long) (buffer[offset + 4] & 0xFF) << 24) | ((long) (buffer[offset + 5] & 0xFF) << 16) | ((long) (buffer[offset + 6] & 0xFF) << 8) | (buffer[offset + 7] & 0xFF);
    }

    /**
     * Extracts text content from the given {@link AbstractFile} and returns it as a list of strings, where each string represents a line from the extracted text.
     *
     * The extraction method depends on the file's MIME type or extension: - For Excel files (.xlsx), uses Apache POI to extract text from all sheets. - For Word documents
     * (.docx), uses Apache POI to extract text from the document. - For PDF files (.pdf), uses PDFBox to extract text from the PDF. - For all other files, extracts ASCII
     * strings from the file's byte content.
     *
     * If no strings are found in the file, an {@link IllegalArgumentException} is thrown.
     *
     * @param file The {@link AbstractFile} to extract strings from. Must not be {@code null}.
     * @return A {@link List} of strings, each representing a line from the extracted text.
     * @throws TskCoreException If an error occurs while reading the file content.
     * @throws IllegalArgumentException If the file is {@code null} or no strings are found in the file.
     */
    public static List<String> extractStringFromFile(AbstractFile file) throws TskCoreException, IllegalArgumentException
    {

        if (file == null)
            throw new IllegalArgumentException("File is null");
        String mime = file.getMIMEType().toLowerCase();
        String ext = file.getNameExtension().toLowerCase();
        if (mime.equals("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet") || ext.equals("xlsx"))
        {
            XSSFWorkbook workbook = null;
            XSSFExcelExtractor extractor = null;
            ReadContentInputStream inStream = new ReadContentInputStream(file);
            try
            {
                workbook = new XSSFWorkbook(inStream);
                extractor = new XSSFExcelExtractor(workbook);
                String str = extractor.getText();
                String lines[] = str.split("\\r?\\n");
                return Arrays.asList(lines);
            }
            catch (IOException e)
            {
            } finally
            {
                try
                {
                    if (extractor != null)
                        extractor.close();
                    if (workbook != null)
                        workbook.close();
                }
                catch (IOException e)
                {
                }

            }
        }
        if (mime.equals("application/vnd.openxmlformats-officedocument.wordprocessingml.document") || ext.equals("docx"))
        {
            XWPFDocument workbook = null;
            XWPFWordExtractor extractor = null;
            ReadContentInputStream inStream = new ReadContentInputStream(file);
            try
            {
                workbook = new XWPFDocument(inStream);
                extractor = new XWPFWordExtractor(workbook);
                String str = extractor.getText();
                String lines[] = str.split("\\r?\\n");
                return Arrays.asList(lines);
            }
            catch (IOException e)
            {
            } finally
            {
                try
                {
                    if (extractor != null)
                        extractor.close();
                    if (workbook != null)
                        workbook.close();
                }
                catch (IOException e)
                {
                }

            }
        }
        byte[] bytes = new byte[(int) file.getSize()];
        file.read(bytes, 0, bytes.length);

        if (mime.equals("application/pdf") || mime.equals("application/x-pdf") || ext.equals("pdf"))
        {
            PDDocument pdfDoc = null;
            try
            {
                pdfDoc = Loader.loadPDF(bytes);
                PDFTextStripper pdfStripper = new PDFTextStripper();
                String str = pdfStripper.getText(pdfDoc);
                String lines[] = str.split("\\r?\\n");
                return Arrays.asList(lines);
            }
            catch (IOException e)
            {
            } finally
            {
                try
                {
                    if (pdfDoc != null)
                        pdfDoc.close();
                }
                catch (IOException e)
                {
                }

            }
        }

        String str = StringExtract.extractASCII(bytes, bytes.length, 0);

        if (str.isEmpty())
            throw new IllegalArgumentException("No strings found in file: " + file.getName());

        String lines[] = str.split("\\r?\\n");
        return Arrays.asList(lines);

    }

}
