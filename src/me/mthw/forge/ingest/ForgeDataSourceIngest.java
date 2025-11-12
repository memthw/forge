package me.mthw.forge.ingest;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress;
import org.sleuthkit.autopsy.ingest.IngestModule;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.Image;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.Volume;
import org.sleuthkit.datamodel.VolumeSystem;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.MessageNotifyUtil;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.autopsy.ingest.IngestServices;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;

import me.mthw.forge.ingest.analyzer.Analyzer;
import me.mthw.forge.ingest.analyzer.volume.VolumeAnalyzerBitlocker;
import me.mthw.forge.ingest.analyzer.volume.VolumeAnalyzerLUKS;

/**
 * The ForgeDataSourceIngest class is an implementation of the DataSourceIngestModule interface, designed to process data sources during the ingest process. This class
 * identifies specific volume types, such as BitLocker and LUKS, within an image and processes them using the appropriate analyzers.
 *
 * Key Features: - Identifies BitLocker and LUKS volumes by analyzing specific byte patterns. - Processes identified volumes using corresponding analyzers. - Handles
 * errors gracefully, logging and notifying issues while continuing to process other volumes or volume systems.
 *
 * Constants: - BITLOCKER_GUID: Byte pattern for identifying BitLocker volumes. - BITLOCKER_TOGO_GUID: Byte pattern for identifying BitLocker To Go volumes. -
 * LUKS_HEADER: Byte pattern for identifying LUKS headers.
 *
 * Methods: - startUp(IngestJobContext context): Initializes the ingest module, setting up the blackboard and creating necessary artifact types. - process(Content
 * dataSource, DataSourceIngestModuleProgress progressBar): Processes the given data source, identifying and analyzing specific volume types. - getMainAttributeType():
 * Retrieves the main attribute type associated with this data source.
 *
 * Error Handling: - Logs and notifies errors encountered during volume or volume system processing. - Continues processing other volumes or volume systems in case of
 * errors. - Returns ERROR if an exception occurs while retrieving volume systems.
 *
 * Note: - The ingest cancellation check is omitted due to the short analysis duration.
 */
public class ForgeDataSourceIngest implements DataSourceIngestModule
{
    // Bitlocker guid (mixed endian - 1-3 LE, 4-5 BE) without last byte for better comparing performance
    // 4967d63b-2e29-4ad8-8399-f6a339e3d00 - BITLOCKER
    // 4967d63b-2e29-4ad8-8399-f6a339e3d01 - BITLOCKER_TO_GO
    public static final byte[] BITLOCKER_GUID = new byte[] { (byte) 0x3b, (byte) 0xd6, (byte) 0x67, (byte) 0x49, (byte) 0x29, (byte) 0x2e, (byte) 0xd8, (byte) 0x4a, (byte) 0x83, (byte) 0x99, (byte) 0xf6, (byte) 0xa3, (byte) 0x39, (byte) 0xe3, (byte) 0xd0 };
    public static final byte[] BITLOCKER_TOGO_GUID = new byte[] { (byte) 0x3b, (byte) 0xd6, (byte) 0x67, (byte) 0x49, (byte) 0x29, (byte) 0x2e, (byte) 0xd8, (byte) 0x4a, (byte) 0x83, (byte) 0x99, (byte) 0xf6, (byte) 0xa3, (byte) 0x39, (byte) 0xe3, (byte) 0xd0 };
    // LUKS header
    // 0x4c 0x55 0x4b 0x53 (LUKS)
    public static final byte[] LUKS_HEADER = new byte[] { (byte) 0x4c, (byte) 0x55, (byte) 0x4b, (byte) 0x53 };

    private IngestJobContext context = null;
    private Blackboard blackboard;
    private Logger logger;
    BlackboardAttribute.Type mainAttribute;

    ForgeDataSourceIngest()
    {
    }

    @Override
    public void startUp(IngestJobContext context) throws IngestModuleException
    {

        this.context = context;
        logger = IngestServices.getInstance().getLogger(ForgeIngestFactory.getModuleName());
        try
        {
            blackboard = Case.getCurrentCaseThrows().getSleuthkitCase().getBlackboard();
            // Same for both data source and file modules. Static method in ForgeIngestFactory
            mainAttribute = ForgeIngestFactory.createBlackboardArtifacts(blackboard);
        }
        catch (BlackboardException ex)
        {

            logger.log(Level.SEVERE, "Error creating artifact type", ex);
            throw new IngestModuleException("Error creating artifact type", ex);
        }
        catch (NoCurrentCaseException ex)
        {
            logger.log(Level.SEVERE, "Error getting case", ex);
            throw new IngestModuleException("Error getting case", ex);
        }

    }

    /**
     * Processes the given data source during the ingest process. This method analyzes the volumes within an image to identify specific volume types, such as BitLocker or
     * LUKS, and processes them using the appropriate analyzer.
     *
     * @param dataSource The data source to be processed, expected to be an instance of Image.
     * @param progressBar The progress bar to update during the processing.
     * @return The result of the processing, either OK or ERROR.
     *
     * The method performs the following steps: - Checks if the data source is an instance of Image. If not, returns OK. - Retrieves the volume systems from the image. -
     * Iterates through each volume system and retrieves its volumes. - For each volume, checks for specific volume types (e.g., BitLocker, LUKS) by reading specific byte
     * patterns from the volume. - If a matching volume type is found, processes the volume using the corresponding analyzer.
     *
     * Error handling: - Logs and notifies errors encountered during volume or volume system processing. - Continues processing other volumes or volume systems in case of
     * errors. - Returns ERROR if an exception occurs while retrieving volume systems.
     *
     * Note: The ingest cancellation check is omitted due to the short analysis duration.
     *
     * Exceptions handled: - TskCoreException - BlackboardException - IllegalAccessError - IOException - NoCurrentCaseException
     */
    @Override
    public ProcessResult process(Content dataSource, DataSourceIngestModuleProgress progressBar)
    {
        // We should be checking ingest is cancelled here, but since the analysis is short and only for the volume we dont check.
        progressBar.switchToIndeterminate();
        if ((dataSource instanceof Image) == false)
        {
            return ProcessResult.OK;
        }
        Image image = (Image) dataSource;
        Analyzer analyzer = null;

        List<VolumeSystem> volumeSystems;
        try
        {
            volumeSystems = image.getVolumeSystems();

            for (VolumeSystem volumeSystem : volumeSystems)
            {
                List<Volume> volumes;
                try
                {
                    volumes = volumeSystem.getVolumes();

                    for (Volume volume : volumes)
                    {
                        try
                        {
                            byte[] bitlockerGuid = new byte[15];
                            byte[] lastByte = new byte[1];
                            volume.read(bitlockerGuid, 160, 15);
                            volume.read(lastByte, 175, 1);
                            // Equals bitlocker guid with last byte 0x00 or 0x01
                            if (Arrays.equals(BITLOCKER_GUID, bitlockerGuid) && (lastByte[0] == 0x00 || lastByte[0] == 0x01))
                            {
                                analyzer = new VolumeAnalyzerBitlocker(mainAttribute, blackboard, context);
                            }

                            // LUKS
                            byte[] luksHeader = new byte[4];
                            volume.read(luksHeader, 0, 4);
                            if (Arrays.equals(LUKS_HEADER, luksHeader))
                            {
                                analyzer = new VolumeAnalyzerLUKS(mainAttribute, blackboard, context);
                            }
                            boolean processed = false;
                            if (analyzer != null)
                                processed = analyzer.process(volume);
                        }
                        catch (TskCoreException | BlackboardException | IllegalAccessError | IOException | NoCurrentCaseException e)
                        {
                            MessageNotifyUtil.Notify.error(": Error processing volume: " + volume.getAddr() + " " + volume.getDescription(), e.getMessage());
                            logger.log(Level.WARNING, "Error processing volume: " + volume.getAddr() + " " + volume.getDescription(), e.getMessage());
                            continue;
                        }
                    }
                }
                catch (TskCoreException e)
                {
                    MessageNotifyUtil.Notify.error(": Error processing volumeSystem: " + volumeSystem.getType().getName(), e.getMessage());
                    logger.log(Level.WARNING, "Error processing volumeSystem: " + volumeSystem.getType().getName(), e.getMessage());
                    continue;
                }
            }
        }
        catch (TskCoreException e)
        {
            MessageNotifyUtil.Notify.error(": Error processing volume", e.getMessage());
            logger.log(Level.WARNING, "Error processing volume", e.getMessage());
            return ProcessResult.ERROR;
        }
        return IngestModule.ProcessResult.OK;
    }

    /**
     * Retrieves the main attribute type associated with this data source.
     *
     * @return The main attribute type as a {@link BlackboardAttribute.Type}.
     */
    public BlackboardAttribute.Type getMainAttributeType()
    {
        return mainAttribute;
    }
}
