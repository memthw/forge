package me.mthw.forge;

import org.sleuthkit.datamodel.BlackboardAttribute;

public class Attribute
{
    public String typeName;
    public BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE type;
    public String displayName;
    public BlackboardAttribute.Type blackoardAttributeType;

    public Attribute(String typeName, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE type, String displayName)
    {
        this.typeName = typeName;
        this.type = type;
        this.displayName = displayName;
    }

    public Attribute(String typeName, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE type, String displayName, BlackboardAttribute.Type blackoardAttributeType)
    {
        this.typeName = typeName;
        this.type = type;
        this.displayName = displayName;
        this.blackoardAttributeType = blackoardAttributeType;
    }
}
