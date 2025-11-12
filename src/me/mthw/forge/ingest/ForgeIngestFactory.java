
package me.mthw.forge.ingest;

import java.util.List;
// The following import is required for the ServiceProvider annotation (see 
// below) used by the Autopsy ingest framework to locate ingest module 
// factories. You will need to add a dependency on the Lookup API NetBeans 
// module to your NetBeans module to use this import.
import org.openide.util.lookup.ServiceProvider;

import org.sleuthkit.autopsy.ingest.IngestModuleFactory;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestModuleGlobalSettingsPanel;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettingsPanel;
import org.sleuthkit.autopsy.ingest.NoIngestModuleIngestJobSettings;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.TskCoreException;

@ServiceProvider(service = IngestModuleFactory.class)
public class ForgeIngestFactory implements IngestModuleFactory
{

    private static final String VERSION_NUMBER = "0.5.0";

    // This class method allows the ingest module instances created by this
    // factory to use the same display name that is provided to the Autopsy
    // ingest framework by the factory.
    public static String getModuleName()
    {
        return "FORGE Ingest Module";
    }

    /**
     * Gets the display name that identifies the family of ingest modules the factory creates. Autopsy uses this string to identify the module in user interface components
     * and log messages. The module name must be unique. so a brief but distinctive name is recommended.
     *
     * @return The module family display name.
     */
    @Override
    public String getModuleDisplayName()
    {
        return getModuleName();
    }

    /**
     * Gets a brief, user-friendly description of the family of ingest modules the factory creates. Autopsy uses this string to describe the module in user interface
     * components.
     *
     * @return The module family description.
     */
    @Override
    public String getModuleDescription()
    {
        return "Module for analyzing and categorizing files for FORGE";
    }

    /**
     * Gets the version number of the family of ingest modules the factory creates.
     *
     * @return The module family version number.
     */
    @Override
    public String getModuleVersionNumber()
    {
        return VERSION_NUMBER;
    }

    /**
     * Queries the factory to determine if it provides a user interface panel to allow a user to change settings that are used by all instances of the family of ingest
     * modules the factory creates. For example, the Autopsy core hash lookup ingest module factory provides a global settings panel to import and create hash databases. The
     * hash databases are then enabled or disabled per ingest job using an ingest job settings panel. If the module family does not have global settings, the factory may
     * extend IngestModuleFactoryAdapter to get an implementation of this method that returns false.
     *
     * @return True if the factory provides a global settings panel.
     */
    @Override
    public boolean hasGlobalSettingsPanel()
    {
        return false;
    }

    /**
     * Gets a user interface panel that allows a user to change settings that are used by all instances of the family of ingest modules the factory creates. For example, the
     * Autopsy core hash lookup ingest module factory provides a global settings panel to import and create hash databases. The imported hash databases are then enabled or
     * disabled per ingest job using ingest an ingest job settings panel. If the module family does not have a global settings, the factory may extend
     * IngestModuleFactoryAdapter to get an implementation of this method that throws an UnsupportedOperationException.
     *
     * @return A global settings panel.
     */
    @Override
    public IngestModuleGlobalSettingsPanel getGlobalSettingsPanel()
    {
        throw new UnsupportedOperationException();
    }

    /**
     * Gets the default per ingest job settings for instances of the family of ingest modules the factory creates. For example, the Autopsy core hash lookup ingest modules
     * family uses hash databases imported or created using its global settings panel. All of the hash databases are enabled by default for an ingest job. If the module
     * family does not have per ingest job settings, the factory may extend IngestModuleFactoryAdapter to get an implementation of this method that returns an instance of the
     * NoIngestModuleJobSettings class.
     *
     * @return The default ingest job settings.
     */
    @Override
    public IngestModuleIngestJobSettings getDefaultIngestJobSettings()
    {
        return new NoIngestModuleIngestJobSettings();
    }

    /**
     * Queries the factory to determine if it provides user a interface panel to allow a user to make per ingest job settings for instances of the family of ingest modules
     * the factory creates. For example, the Autopsy core hash lookup ingest module factory provides an ingest job settings panels to enable or disable hash databases per
     * ingest job. If the module family does not have per ingest job settings, the factory may extend IngestModuleFactoryAdapter to get an implementation of this method that
     * returns false.
     *
     * @return True if the factory provides ingest job settings panels.
     */
    @Override
    public boolean hasIngestJobSettingsPanel()
    {
        return false;
    }

    /**
     * Gets a user interface panel that can be used to set per ingest job settings for instances of the family of ingest modules the factory creates. For example, the core
     * hash lookup ingest module factory provides an ingest job settings panel to enable or disable hash databases per ingest job. If the module family does not have per
     * ingest job settings, the factory may extend IngestModuleFactoryAdapter to get an implementation of this method that throws an UnsupportedOperationException.
     *
     * @param settings Per ingest job settings to initialize the panel.
     *
     * @return An ingest job settings panel.
     */
    @Override
    public IngestModuleIngestJobSettingsPanel getIngestJobSettingsPanel(IngestModuleIngestJobSettings settings)
    {
        throw new UnsupportedOperationException();
    }

    /**
     * Queries the factory to determine if it is capable of creating data source ingest modules. If the module family does not include data source ingest modules, the factory
     * may extend IngestModuleFactoryAdapter to get an implementation of this method that returns false.
     *
     * @return True if the factory can create data source ingest modules.
     */
    @Override
    public boolean isDataSourceIngestModuleFactory()
    {
        return true;
    }

    /**
     * Creates a data source ingest module instance.
     * Autopsy will generally use the factory to several instances of each type of module for each ingest job it performs. Completing an ingest job entails processing a
     * single data source (e.g., a disk image) and all of the files from the data source, including files extracted from archives and any unallocated space (made to look like
     * a series of files). The data source is passed through one or more pipelines of data source ingest modules. The files are passed through one or more pipelines of file
     * ingest modules.
     * The ingest framework may use multiple threads to complete an ingest job, but it is guaranteed that there will be no more than one module instance per thread. However,
     * if the module instances must share resources, the modules are responsible for synchronizing access to the shared resources and doing reference counting as required to
     * release those resources correctly. Also, more than one ingest job may be in progress at any given time. This must also be taken into consideration when sharing
     * resources between module instances. modules.
     * If the module family does not include data source ingest modules, the factory may extend IngestModuleFactoryAdapter to get an implementation of this method that throws
     * an UnsupportedOperationException.
     *
     * @param settings The settings for the ingest job.
     *
     * @return A data source ingest module instance.
     */
    @Override
    public DataSourceIngestModule createDataSourceIngestModule(IngestModuleIngestJobSettings settings)
    {
        return new ForgeDataSourceIngest();
    }

    /**
     * Queries the factory to determine if it is capable of creating file ingest modules. If the module family does not include file ingest modules, the factory
     * may extend IngestModuleFactoryAdapter to get an implementation of this method that returns false.
     *
     * @return True if the factory can create file ingest modules.
     */
    @Override
    public boolean isFileIngestModuleFactory()
    {
        return true;
    }


    /**
     * Creates a new instance of a file ingest module.
     *
     * @param settings The settings for the ingest job.
     * @return A new instance of {@link ForgeFileIngest}.

     */
    @Override
    public FileIngestModule createFileIngestModule(IngestModuleIngestJobSettings settings)
    {
        return new ForgeFileIngest();
    }

    /**
     * Adds a main flag attribute to the general information artifact of the given content file.
     * This method is synchronized to ensure thread safety.
     *
     * @param file           The content file to which the main flag attribute will be added.
     * @param mainAttribute  The type of the main flag attribute to add.
     * @throws TskCoreException         If there is an error accessing or modifying the artifact.
     * @throws IllegalArgumentException If the provided arguments are invalid.
     * 
     * Note: If the general information artifact of the file already contains the specified
     *       main flag attribute, this method will return without making any changes.
     */
    public static synchronized void addMainFlag(Content file, BlackboardAttribute.Type mainAttribute) throws TskCoreException, IllegalArgumentException
    {
            //Already has the attribute
            if (file.getGenInfoArtifact(true).getAttribute(mainAttribute) != null)
                return;
            file.getGenInfoArtifact(true).addAttribute(new BlackboardAttribute(mainAttribute, ForgeIngestFactory.getModuleName(), "true"));
    }

    /**
     * Adds a main flag to a list of content files based on the specified main attribute.
     * This method is synchronized to ensure thread safety.
     *
     * @param files          The list of content files to which the main flag will be added.
     * @param mainAttribute  The main attribute used to determine the flag to be added.
     * @throws TskCoreException         If an error occurs while adding the main flag.
     * @throws IllegalArgumentException If the provided arguments are invalid.
     */
    public static synchronized void addMainFlag(List<Content> files, BlackboardAttribute.Type mainAttribute) throws TskCoreException, IllegalArgumentException
    {
        for (Content file : files)
            addMainFlag(file, mainAttribute);
    }

    /**
     * Creates or retrieves a blackboard attribute type with the main type name, value type, and display name.
     * This method ensures thread safety by being synchronized.
     *
     * @param blackboard The blackboard instance where the attribute type will be created or retrieved.
     * @return The blackboard attribute type created or retrieved.
     * @throws BlackboardException If there is an error creating or retrieving the attribute type.
     * @throws NoCurrentCaseException If there is no current case context available.
     */
    public static synchronized BlackboardAttribute.Type createBlackboardArtifacts(Blackboard blackboard) throws BlackboardException, NoCurrentCaseException
    {
        return blackboard.getOrAddAttributeType("FORGE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "FORGE");
    }

}