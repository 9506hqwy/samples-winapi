#pragma comment(lib, "Cfgmgr32")

#pragma warning(disable : 4464)
#pragma warning(once : 4710)
#pragma warning(once : 4711)
#pragma warning(disable : 5045)

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <cfgmgr32.h>
#include <initguid.h>
#include <devpropdef.h>
#include <devpkey.h>
#include "../common/console.h"
#include "../common/string.h"

int EnumerateEnumerators(HANDLE);
int EnumerateIdList(HANDLE, LPTSTR);
int EnumeratePropList(HANDLE, LPTSTR);
int GetPropValue(HANDLE, LPTSTR, LPTSTR);
CONFIGRET GetDevMode(HANDLE, LPTSTR, PDEVINST *);
const DEVPROPKEY *GetPropKey(TCHAR *name);
TCHAR *GetPropName(PDEVPROPKEY key);
BOOL WritePropValue(HANDLE, DEVPROPTYPE, PBYTE, ULONG);

#define KeyToName(prop)                                                                                                \
    if (IsEqualDevPropKey(*key, (DEVPKEY_##prop)))                                                                     \
    {                                                                                                                  \
        return TEXT(#prop);                                                                                            \
    }

#define NameToKey(name, prop)                                                                                          \
    if (!lstrcmp(name, TEXT(#prop)))                                                                                   \
    {                                                                                                                  \
        return &(DEVPKEY_##prop);                                                                                      \
    }

#define MODE_NONE 0
#define MODE_ENUMERATORS 1
#define MODE_IDLIST 2
#define MODE_PROPLIST 3
#define MODE_PROPVALUE 4

#ifdef UNICODE
int wmain(int argc, TCHAR *argv[])
#else
int main(int argc, TCHAR *argv[])
#endif
{
    int mode = MODE_NONE;
    LPTSTR filter = NULL;
    LPTSTR id = NULL;
    LPTSTR prop = NULL;

    LPTSTR *arg = NULL;
    for (arg = argv + 1; (arg - argv) < argc; arg += 1)
    {
        if (*arg[0] != '-')
        {
            continue;
        }
        else if (!lstrcmp(*arg, TEXT("-e")))
        {
            mode = MODE_ENUMERATORS;
            break;
        }
        else if (!lstrcmp(*arg, TEXT("-l")))
        {
            arg += 1;
            filter = *arg;

            mode = MODE_IDLIST;
            break;
        }
        else if (!lstrcmp(*arg, TEXT("-p")))
        {
            arg += 1;
            id = *arg;

            mode = MODE_PROPLIST;
            break;
        }
        else if (!lstrcmp(*arg, TEXT("-v")))
        {
            arg += 1;
            id = *arg;

            arg += 1;
            prop = *arg;

            mode = MODE_PROPVALUE;
            break;
        }
        else
        {
            WriteStdErr(TEXT("Error: unknown option '%s'\n"), *arg);
            return 1;
        }
    }

    int exitCode = 0;

    HANDLE heap = HeapCreate(0, 0, 0);

    switch (mode)
    {
    case MODE_NONE:
        break;
    case MODE_ENUMERATORS:
        exitCode = EnumerateEnumerators(heap);
        break;
    case MODE_IDLIST:
        exitCode = EnumerateIdList(heap, filter);
        break;
    case MODE_PROPLIST:
        exitCode = EnumeratePropList(heap, id);
        break;
    case MODE_PROPVALUE:
        exitCode = GetPropValue(heap, id, prop);
        break;
    }

    HeapDestroy(heap);

    return exitCode;
}

int EnumerateEnumerators(HANDLE heap)
{
    CONFIGRET ret = 0;
    ULONG index = 0;
    while (TRUE)
    {
        TCHAR zero = 0;
        ULONG length = 0;
        ret = CM_Enumerate_Enumerators(index, &zero, &length, 0);
        if (CR_NO_SUCH_VALUE == ret)
        {
            break;
        }
        else if (CR_BUFFER_SMALL != ret)
        {
            // occur `CR_INVALID_DATA` when /DUNICODE is on.
            WriteSystemError(CM_MapCrToWin32Err(ret, ERROR_INVALID_DATA));
            return -1;
        }

        LPTSTR buffer = (LPTSTR)HeapAlloc(heap, HEAP_ZERO_MEMORY, length * sizeof(TCHAR));
        if (buffer == NULL)
        {
            return -2;
        }

        ret = CM_Enumerate_Enumerators(index, buffer, &length, 0);
        if (CR_SUCCESS != ret)
        {
            WriteSystemError(CM_MapCrToWin32Err(ret, ERROR_INVALID_DATA));
            HeapFree(heap, 0, buffer);
            return -3;
        }

        if (!WriteStdOut(TEXT("%s\n"), buffer))
        {
            WriteLastSystemError();
            HeapFree(heap, 0, buffer);
            return -4;
        }

        HeapFree(heap, 0, buffer);

        index += 1;
    }

    return 0;
}

int EnumerateIdList(HANDLE heap, LPTSTR filter)
{
    ULONG flags = CM_GETIDLIST_FILTER_ENUMERATOR | CM_GETIDLIST_FILTER_PRESENT;

    ULONG size = 0;
    CONFIGRET ret = CM_Get_Device_ID_List_Size(&size, filter, flags);
    if (CR_SUCCESS != ret)
    {
        WriteSystemError(CM_MapCrToWin32Err(ret, ERROR_INVALID_DATA));
        return -1;
    }

    PZZTSTR buffer = (PZZTSTR)HeapAlloc(heap, HEAP_ZERO_MEMORY, size * sizeof(TCHAR));
    if (buffer == NULL)
    {
        return -2;
    }

    ret = CM_Get_Device_ID_List(filter, buffer, size, flags);
    if (CR_SUCCESS != ret)
    {
        WriteSystemError(CM_MapCrToWin32Err(ret, ERROR_INVALID_DATA));
        HeapFree(heap, 0, buffer);
        return -3;
    }

    for (DEVINSTID id = buffer; *id != 0; id += lstrlen(id) + 1)
    {
        if (!WriteStdOut(TEXT("%s\n"), id))
        {
            WriteLastSystemError();
            HeapFree(heap, 0, buffer);
            return -4;
        }
    }

    HeapFree(heap, 0, buffer);
    return 0;
}

int EnumeratePropList(HANDLE heap, LPTSTR id)
{
    PDEVINST devNode = NULL;
    CONFIGRET ret = GetDevMode(heap, id, &devNode);
    if (CR_SUCCESS != ret)
    {
        WriteSystemError(CM_MapCrToWin32Err(ret, ERROR_INVALID_DATA));
        return -1;
    }

    ULONG size = 0;
    ret = CM_Get_DevNode_Property_Keys(*devNode, NULL, &size, 0);
    if (CR_BUFFER_SMALL != ret)
    {
        WriteSystemError(CM_MapCrToWin32Err(ret, ERROR_INVALID_DATA));
        HeapFree(heap, 0, devNode);
        return -2;
    }

    PDEVPROPKEY propKeys = (PDEVPROPKEY)HeapAlloc(heap, HEAP_ZERO_MEMORY, size * sizeof(DEVPROPKEY));
    if (propKeys == NULL)
    {
        HeapFree(heap, 0, devNode);
        return -3;
    }

    ret = CM_Get_DevNode_Property_Keys(*devNode, propKeys, &size, 0);
    if (CR_SUCCESS != ret)
    {
        WriteSystemError(CM_MapCrToWin32Err(ret, ERROR_INVALID_DATA));
        HeapFree(heap, 0, propKeys);
        HeapFree(heap, 0, devNode);
        return -4;
    }

    for (ULONG i = 0; i < size; i++)
    {
        WriteStdOut(TEXT("%s\n"), GetPropName(propKeys + i));
    }

    HeapFree(heap, 0, propKeys);
    HeapFree(heap, 0, devNode);
    return 0;
}

int GetPropValue(HANDLE heap, LPTSTR id, LPTSTR prop)
{
    PDEVINST devNode = NULL;
    CONFIGRET ret = GetDevMode(heap, id, &devNode);
    if (CR_SUCCESS != ret)
    {
        WriteSystemError(CM_MapCrToWin32Err(ret, ERROR_INVALID_DATA));
        return -1;
    }

    const DEVPROPKEY *key = GetPropKey(prop);
    if (key == NULL)
    {
        WriteStdErr(TEXT("Not found property key '%s'\n"), prop);
        HeapFree(heap, 0, devNode);
        return -2;
    }

    ULONG size = 0;
    DEVPROPTYPE propType = {0};
    ret = CM_Get_DevNode_PropertyW(*devNode, key, &propType, NULL, &size, 0);
    if (CR_BUFFER_SMALL != ret)
    {
        WriteSystemError(CM_MapCrToWin32Err(ret, ERROR_INVALID_DATA));
        HeapFree(heap, 0, devNode);
        return -3;
    }

    PBYTE value = (PBYTE)HeapAlloc(heap, HEAP_ZERO_MEMORY, size * sizeof(BYTE));
    if (NULL == value)
    {
        WriteLastSystemError();
        HeapFree(heap, 0, devNode);
        return -4;
    }

    ret = CM_Get_DevNode_PropertyW(*devNode, key, &propType, value, &size, 0);
    if (CR_SUCCESS != ret)
    {
        WriteSystemError(CM_MapCrToWin32Err(ret, ERROR_INVALID_DATA));
        HeapFree(heap, 0, value);
        HeapFree(heap, 0, devNode);
        return -5;
    }

    if (!WritePropValue(heap, propType, value, size))
    {
        WriteLastSystemError();
        HeapFree(heap, 0, value);
        HeapFree(heap, 0, devNode);
        return -6;
    }

    HeapFree(heap, 0, value);
    HeapFree(heap, 0, devNode);
    return 0;
}

// -----------------------------------------------------------------------------------------------

CONFIGRET GetDevMode(HANDLE heap, LPTSTR id, PDEVINST *devNode)
{
    *devNode = (PDEVINST)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(DEVINST));
    if (devNode == NULL)
    {
        return CR_OUT_OF_MEMORY;
    }

    CONFIGRET ret = CM_Locate_DevNode(*devNode, id, CM_LOCATE_DEVNODE_NORMAL);
    if (CR_SUCCESS != ret)
    {
        HeapFree(heap, 0, *devNode);
        *devNode = NULL;
    }

    return ret;
}

const DEVPROPKEY *GetPropKey(TCHAR *name)
{
    NameToKey(name, NAME);
    NameToKey(name, Device_DeviceDesc);
    NameToKey(name, Device_HardwareIds);
    NameToKey(name, Device_CompatibleIds);
    NameToKey(name, Device_Service);
    NameToKey(name, Device_Class);
    NameToKey(name, Device_ClassGuid);
    NameToKey(name, Device_Driver);
    NameToKey(name, Device_ConfigFlags);
    NameToKey(name, Device_Manufacturer);
    NameToKey(name, Device_FriendlyName);
    NameToKey(name, Device_LocationInfo);
    NameToKey(name, Device_PDOName);
    NameToKey(name, Device_Capabilities);
    NameToKey(name, Device_UINumber);
    NameToKey(name, Device_UpperFilters);
    NameToKey(name, Device_LowerFilters);
    NameToKey(name, Device_BusTypeGuid);
    NameToKey(name, Device_LegacyBusType);
    NameToKey(name, Device_BusNumber);
    NameToKey(name, Device_EnumeratorName);
    NameToKey(name, Device_Security);
    NameToKey(name, Device_SecuritySDS);
    NameToKey(name, Device_DevType);
    NameToKey(name, Device_Exclusive);
    NameToKey(name, Device_Characteristics);
    NameToKey(name, Device_Address);
    NameToKey(name, Device_UINumberDescFormat);
    NameToKey(name, Device_PowerData);
    NameToKey(name, Device_RemovalPolicy);
    NameToKey(name, Device_RemovalPolicyDefault);
    NameToKey(name, Device_RemovalPolicyOverride);
    NameToKey(name, Device_InstallState);
    NameToKey(name, Device_LocationPaths);
    NameToKey(name, Device_BaseContainerId);
    NameToKey(name, Device_InstanceId);
    NameToKey(name, Device_DevNodeStatus);
    NameToKey(name, Device_ProblemCode);
    NameToKey(name, Device_EjectionRelations);
    NameToKey(name, Device_RemovalRelations);
    NameToKey(name, Device_PowerRelations);
    NameToKey(name, Device_BusRelations);
    NameToKey(name, Device_Parent);
    NameToKey(name, Device_Children);
    NameToKey(name, Device_Siblings);
    NameToKey(name, Device_TransportRelations);
    NameToKey(name, Device_ProblemStatus);
    NameToKey(name, Device_Reported);
    NameToKey(name, Device_Legacy);
    NameToKey(name, Device_ContainerId);
    NameToKey(name, Device_InLocalMachineContainer);
    NameToKey(name, Device_Model);
    NameToKey(name, Device_ModelId);
    NameToKey(name, Device_FriendlyNameAttributes);
    NameToKey(name, Device_ManufacturerAttributes);
    NameToKey(name, Device_PresenceNotForDevice);
    NameToKey(name, Device_SignalStrength);
    NameToKey(name, Device_IsAssociateableByUserAction);
    NameToKey(name, Device_ShowInUninstallUI);
    NameToKey(name, Device_Numa_Proximity_Domain);
    NameToKey(name, Device_DHP_Rebalance_Policy);
    NameToKey(name, Device_Numa_Node);
    NameToKey(name, Device_BusReportedDeviceDesc);
    NameToKey(name, Device_IsPresent);
    NameToKey(name, Device_HasProblem);
    NameToKey(name, Device_ConfigurationId);
    NameToKey(name, Device_ReportedDeviceIdsHash);
    NameToKey(name, Device_PhysicalDeviceLocation);
    NameToKey(name, Device_BiosDeviceName);
    NameToKey(name, Device_DriverProblemDesc);
    NameToKey(name, Device_DebuggerSafe);
    NameToKey(name, Device_PostInstallInProgress);
    NameToKey(name, Device_Stack);
    NameToKey(name, Device_ExtendedConfigurationIds);
    NameToKey(name, Device_IsRebootRequired);
    NameToKey(name, Device_FirmwareDate);
    NameToKey(name, Device_FirmwareVersion);
    NameToKey(name, Device_FirmwareRevision);
    NameToKey(name, Device_DependencyProviders);
    NameToKey(name, Device_DependencyDependents);
    NameToKey(name, Device_SoftRestartSupported);
    NameToKey(name, Device_ExtendedAddress);
    NameToKey(name, Device_AssignedToGuest);
    NameToKey(name, Device_SessionId);
    NameToKey(name, Device_InstallDate);
    NameToKey(name, Device_FirstInstallDate);
    NameToKey(name, Device_LastArrivalDate);
    NameToKey(name, Device_LastRemovalDate);
    NameToKey(name, Device_DriverDate);
    NameToKey(name, Device_DriverVersion);
    NameToKey(name, Device_DriverDesc);
    NameToKey(name, Device_DriverInfPath);
    NameToKey(name, Device_DriverInfSection);
    NameToKey(name, Device_DriverInfSectionExt);
    NameToKey(name, Device_MatchingDeviceId);
    NameToKey(name, Device_DriverProvider);
    NameToKey(name, Device_DriverPropPageProvider);
    NameToKey(name, Device_DriverCoInstallers);
    NameToKey(name, Device_ResourcePickerTags);
    NameToKey(name, Device_ResourcePickerExceptions);
    NameToKey(name, Device_DriverRank);
    NameToKey(name, Device_DriverLogoLevel);
    NameToKey(name, Device_NoConnectSound);
    NameToKey(name, Device_GenericDriverInstalled);
    NameToKey(name, Device_AdditionalSoftwareRequested);
    NameToKey(name, Device_SafeRemovalRequired);
    NameToKey(name, Device_SafeRemovalRequiredOverride);
    NameToKey(name, DrvPkg_Model);
    NameToKey(name, DrvPkg_VendorWebSite);
    NameToKey(name, DrvPkg_DetailedDescription);
    NameToKey(name, DrvPkg_DocumentationLink);
    NameToKey(name, DrvPkg_Icon);
    NameToKey(name, DrvPkg_BrandingIcon);
    NameToKey(name, DeviceClass_UpperFilters);
    NameToKey(name, DeviceClass_LowerFilters);
    NameToKey(name, DeviceClass_Security);
    NameToKey(name, DeviceClass_SecuritySDS);
    NameToKey(name, DeviceClass_DevType);
    NameToKey(name, DeviceClass_Exclusive);
    NameToKey(name, DeviceClass_Characteristics);
    NameToKey(name, DeviceClass_Name);
    NameToKey(name, DeviceClass_ClassName);
    NameToKey(name, DeviceClass_Icon);
    NameToKey(name, DeviceClass_ClassInstaller);
    NameToKey(name, DeviceClass_PropPageProvider);
    NameToKey(name, DeviceClass_NoInstallClass);
    NameToKey(name, DeviceClass_NoDisplayClass);
    NameToKey(name, DeviceClass_SilentInstall);
    NameToKey(name, DeviceClass_NoUseClass);
    NameToKey(name, DeviceClass_DefaultService);
    NameToKey(name, DeviceClass_IconPath);
    NameToKey(name, DeviceClass_DHPRebalanceOptOut);
    NameToKey(name, DeviceClass_ClassCoInstallers);
    NameToKey(name, DeviceInterface_FriendlyName);
    NameToKey(name, DeviceInterface_Enabled);
    NameToKey(name, DeviceInterface_ClassGuid);
    NameToKey(name, DeviceInterface_ReferenceString);
    NameToKey(name, DeviceInterface_Restricted);
    NameToKey(name, DeviceInterface_UnrestrictedAppCapabilities);
    NameToKey(name, DeviceInterface_SchematicName);
    NameToKey(name, DeviceInterfaceClass_DefaultInterface);
    NameToKey(name, DeviceInterfaceClass_Name);
    NameToKey(name, DeviceContainer_Address);
    NameToKey(name, DeviceContainer_DiscoveryMethod);
    NameToKey(name, DeviceContainer_IsEncrypted);
    NameToKey(name, DeviceContainer_IsAuthenticated);
    NameToKey(name, DeviceContainer_IsConnected);
    NameToKey(name, DeviceContainer_IsPaired);
    NameToKey(name, DeviceContainer_Icon);
    NameToKey(name, DeviceContainer_Version);
    NameToKey(name, DeviceContainer_Last_Seen);
    NameToKey(name, DeviceContainer_Last_Connected);
    NameToKey(name, DeviceContainer_IsShowInDisconnectedState);
    NameToKey(name, DeviceContainer_IsLocalMachine);
    NameToKey(name, DeviceContainer_MetadataPath);
    NameToKey(name, DeviceContainer_IsMetadataSearchInProgress);
    NameToKey(name, DeviceContainer_MetadataChecksum);
    NameToKey(name, DeviceContainer_IsNotInterestingForDisplay);
    NameToKey(name, DeviceContainer_LaunchDeviceStageOnDeviceConnect);
    NameToKey(name, DeviceContainer_LaunchDeviceStageFromExplorer);
    NameToKey(name, DeviceContainer_BaselineExperienceId);
    NameToKey(name, DeviceContainer_IsDeviceUniquelyIdentifiable);
    NameToKey(name, DeviceContainer_AssociationArray);
    NameToKey(name, DeviceContainer_DeviceDescription1);
    NameToKey(name, DeviceContainer_DeviceDescription2);
    NameToKey(name, DeviceContainer_HasProblem);
    NameToKey(name, DeviceContainer_IsSharedDevice);
    NameToKey(name, DeviceContainer_IsNetworkDevice);
    NameToKey(name, DeviceContainer_IsDefaultDevice);
    NameToKey(name, DeviceContainer_MetadataCabinet);
    NameToKey(name, DeviceContainer_RequiresPairingElevation);
    NameToKey(name, DeviceContainer_ExperienceId);
    NameToKey(name, DeviceContainer_Category);
    NameToKey(name, DeviceContainer_Category_Desc_Singular);
    NameToKey(name, DeviceContainer_Category_Desc_Plural);
    NameToKey(name, DeviceContainer_Category_Icon);
    NameToKey(name, DeviceContainer_CategoryGroup_Desc);
    NameToKey(name, DeviceContainer_CategoryGroup_Icon);
    NameToKey(name, DeviceContainer_PrimaryCategory);
    NameToKey(name, DeviceContainer_UnpairUninstall);
    NameToKey(name, DeviceContainer_RequiresUninstallElevation);
    NameToKey(name, DeviceContainer_DeviceFunctionSubRank);
    NameToKey(name, DeviceContainer_AlwaysShowDeviceAsConnected);
    NameToKey(name, DeviceContainer_ConfigFlags);
    NameToKey(name, DeviceContainer_PrivilegedPackageFamilyNames);
    NameToKey(name, DeviceContainer_CustomPrivilegedPackageFamilyNames);
    NameToKey(name, DeviceContainer_IsRebootRequired);
    NameToKey(name, DeviceContainer_FriendlyName);
    NameToKey(name, DeviceContainer_Manufacturer);
    NameToKey(name, DeviceContainer_ModelName);
    NameToKey(name, DeviceContainer_ModelNumber);
    NameToKey(name, DeviceContainer_InstallInProgress);
    NameToKey(name, DevQuery_ObjectType);

    return NULL;
}

TCHAR *GetPropName(PDEVPROPKEY key)
{
    KeyToName(NAME);
    KeyToName(Device_DeviceDesc);
    KeyToName(Device_HardwareIds);
    KeyToName(Device_CompatibleIds);
    KeyToName(Device_Service);
    KeyToName(Device_Class);
    KeyToName(Device_ClassGuid);
    KeyToName(Device_Driver);
    KeyToName(Device_ConfigFlags);
    KeyToName(Device_Manufacturer);
    KeyToName(Device_FriendlyName);
    KeyToName(Device_LocationInfo);
    KeyToName(Device_PDOName);
    KeyToName(Device_Capabilities);
    KeyToName(Device_UINumber);
    KeyToName(Device_UpperFilters);
    KeyToName(Device_LowerFilters);
    KeyToName(Device_BusTypeGuid);
    KeyToName(Device_LegacyBusType);
    KeyToName(Device_BusNumber);
    KeyToName(Device_EnumeratorName);
    KeyToName(Device_Security);
    KeyToName(Device_SecuritySDS);
    KeyToName(Device_DevType);
    KeyToName(Device_Exclusive);
    KeyToName(Device_Characteristics);
    KeyToName(Device_Address);
    KeyToName(Device_UINumberDescFormat);
    KeyToName(Device_PowerData);
    KeyToName(Device_RemovalPolicy);
    KeyToName(Device_RemovalPolicyDefault);
    KeyToName(Device_RemovalPolicyOverride);
    KeyToName(Device_InstallState);
    KeyToName(Device_LocationPaths);
    KeyToName(Device_BaseContainerId);
    KeyToName(Device_InstanceId);
    KeyToName(Device_DevNodeStatus);
    KeyToName(Device_ProblemCode);
    KeyToName(Device_EjectionRelations);
    KeyToName(Device_RemovalRelations);
    KeyToName(Device_PowerRelations);
    KeyToName(Device_BusRelations);
    KeyToName(Device_Parent);
    KeyToName(Device_Children);
    KeyToName(Device_Siblings);
    KeyToName(Device_TransportRelations);
    KeyToName(Device_ProblemStatus);
    KeyToName(Device_Reported);
    KeyToName(Device_Legacy);
    KeyToName(Device_ContainerId);
    KeyToName(Device_InLocalMachineContainer);
    KeyToName(Device_Model);
    KeyToName(Device_ModelId);
    KeyToName(Device_FriendlyNameAttributes);
    KeyToName(Device_ManufacturerAttributes);
    KeyToName(Device_PresenceNotForDevice);
    KeyToName(Device_SignalStrength);
    KeyToName(Device_IsAssociateableByUserAction);
    KeyToName(Device_ShowInUninstallUI);
    KeyToName(Device_Numa_Proximity_Domain);
    KeyToName(Device_DHP_Rebalance_Policy);
    KeyToName(Device_Numa_Node);
    KeyToName(Device_BusReportedDeviceDesc);
    KeyToName(Device_IsPresent);
    KeyToName(Device_HasProblem);
    KeyToName(Device_ConfigurationId);
    KeyToName(Device_ReportedDeviceIdsHash);
    KeyToName(Device_PhysicalDeviceLocation);
    KeyToName(Device_BiosDeviceName);
    KeyToName(Device_DriverProblemDesc);
    KeyToName(Device_DebuggerSafe);
    KeyToName(Device_PostInstallInProgress);
    KeyToName(Device_Stack);
    KeyToName(Device_ExtendedConfigurationIds);
    KeyToName(Device_IsRebootRequired);
    KeyToName(Device_FirmwareDate);
    KeyToName(Device_FirmwareVersion);
    KeyToName(Device_FirmwareRevision);
    KeyToName(Device_DependencyProviders);
    KeyToName(Device_DependencyDependents);
    KeyToName(Device_SoftRestartSupported);
    KeyToName(Device_ExtendedAddress);
    KeyToName(Device_AssignedToGuest);
    KeyToName(Device_SessionId);
    KeyToName(Device_InstallDate);
    KeyToName(Device_FirstInstallDate);
    KeyToName(Device_LastArrivalDate);
    KeyToName(Device_LastRemovalDate);
    KeyToName(Device_DriverDate);
    KeyToName(Device_DriverVersion);
    KeyToName(Device_DriverDesc);
    KeyToName(Device_DriverInfPath);
    KeyToName(Device_DriverInfSection);
    KeyToName(Device_DriverInfSectionExt);
    KeyToName(Device_MatchingDeviceId);
    KeyToName(Device_DriverProvider);
    KeyToName(Device_DriverPropPageProvider);
    KeyToName(Device_DriverCoInstallers);
    KeyToName(Device_ResourcePickerTags);
    KeyToName(Device_ResourcePickerExceptions);
    KeyToName(Device_DriverRank);
    KeyToName(Device_DriverLogoLevel);
    KeyToName(Device_NoConnectSound);
    KeyToName(Device_GenericDriverInstalled);
    KeyToName(Device_AdditionalSoftwareRequested);
    KeyToName(Device_SafeRemovalRequired);
    KeyToName(Device_SafeRemovalRequiredOverride);
    KeyToName(DrvPkg_Model);
    KeyToName(DrvPkg_VendorWebSite);
    KeyToName(DrvPkg_DetailedDescription);
    KeyToName(DrvPkg_DocumentationLink);
    KeyToName(DrvPkg_Icon);
    KeyToName(DrvPkg_BrandingIcon);
    KeyToName(DeviceClass_UpperFilters);
    KeyToName(DeviceClass_LowerFilters);
    KeyToName(DeviceClass_Security);
    KeyToName(DeviceClass_SecuritySDS);
    KeyToName(DeviceClass_DevType);
    KeyToName(DeviceClass_Exclusive);
    KeyToName(DeviceClass_Characteristics);
    KeyToName(DeviceClass_Name);
    KeyToName(DeviceClass_ClassName);
    KeyToName(DeviceClass_Icon);
    KeyToName(DeviceClass_ClassInstaller);
    KeyToName(DeviceClass_PropPageProvider);
    KeyToName(DeviceClass_NoInstallClass);
    KeyToName(DeviceClass_NoDisplayClass);
    KeyToName(DeviceClass_SilentInstall);
    KeyToName(DeviceClass_NoUseClass);
    KeyToName(DeviceClass_DefaultService);
    KeyToName(DeviceClass_IconPath);
    KeyToName(DeviceClass_DHPRebalanceOptOut);
    KeyToName(DeviceClass_ClassCoInstallers);
    KeyToName(DeviceInterface_FriendlyName);
    KeyToName(DeviceInterface_Enabled);
    KeyToName(DeviceInterface_ClassGuid);
    KeyToName(DeviceInterface_ReferenceString);
    KeyToName(DeviceInterface_Restricted);
    KeyToName(DeviceInterface_UnrestrictedAppCapabilities);
    KeyToName(DeviceInterface_SchematicName);
    KeyToName(DeviceInterfaceClass_DefaultInterface);
    KeyToName(DeviceInterfaceClass_Name);
    KeyToName(DeviceContainer_Address);
    KeyToName(DeviceContainer_DiscoveryMethod);
    KeyToName(DeviceContainer_IsEncrypted);
    KeyToName(DeviceContainer_IsAuthenticated);
    KeyToName(DeviceContainer_IsConnected);
    KeyToName(DeviceContainer_IsPaired);
    KeyToName(DeviceContainer_Icon);
    KeyToName(DeviceContainer_Version);
    KeyToName(DeviceContainer_Last_Seen);
    KeyToName(DeviceContainer_Last_Connected);
    KeyToName(DeviceContainer_IsShowInDisconnectedState);
    KeyToName(DeviceContainer_IsLocalMachine);
    KeyToName(DeviceContainer_MetadataPath);
    KeyToName(DeviceContainer_IsMetadataSearchInProgress);
    KeyToName(DeviceContainer_MetadataChecksum);
    KeyToName(DeviceContainer_IsNotInterestingForDisplay);
    KeyToName(DeviceContainer_LaunchDeviceStageOnDeviceConnect);
    KeyToName(DeviceContainer_LaunchDeviceStageFromExplorer);
    KeyToName(DeviceContainer_BaselineExperienceId);
    KeyToName(DeviceContainer_IsDeviceUniquelyIdentifiable);
    KeyToName(DeviceContainer_AssociationArray);
    KeyToName(DeviceContainer_DeviceDescription1);
    KeyToName(DeviceContainer_DeviceDescription2);
    KeyToName(DeviceContainer_HasProblem);
    KeyToName(DeviceContainer_IsSharedDevice);
    KeyToName(DeviceContainer_IsNetworkDevice);
    KeyToName(DeviceContainer_IsDefaultDevice);
    KeyToName(DeviceContainer_MetadataCabinet);
    KeyToName(DeviceContainer_RequiresPairingElevation);
    KeyToName(DeviceContainer_ExperienceId);
    KeyToName(DeviceContainer_Category);
    KeyToName(DeviceContainer_Category_Desc_Singular);
    KeyToName(DeviceContainer_Category_Desc_Plural);
    KeyToName(DeviceContainer_Category_Icon);
    KeyToName(DeviceContainer_CategoryGroup_Desc);
    KeyToName(DeviceContainer_CategoryGroup_Icon);
    KeyToName(DeviceContainer_PrimaryCategory);
    KeyToName(DeviceContainer_UnpairUninstall);
    KeyToName(DeviceContainer_RequiresUninstallElevation);
    KeyToName(DeviceContainer_DeviceFunctionSubRank);
    KeyToName(DeviceContainer_AlwaysShowDeviceAsConnected);
    KeyToName(DeviceContainer_ConfigFlags);
    KeyToName(DeviceContainer_PrivilegedPackageFamilyNames);
    KeyToName(DeviceContainer_CustomPrivilegedPackageFamilyNames);
    KeyToName(DeviceContainer_IsRebootRequired);
    KeyToName(DeviceContainer_FriendlyName);
    KeyToName(DeviceContainer_Manufacturer);
    KeyToName(DeviceContainer_ModelName);
    KeyToName(DeviceContainer_ModelNumber);
    KeyToName(DeviceContainer_InstallInProgress);
    KeyToName(DevQuery_ObjectType);

    return TEXT("Unknown");
}

BOOL WritePropValue(HANDLE heap, DEVPROPTYPE type, PBYTE value, ULONG size)
{
    switch (type)
    {
    case DEVPROP_TYPE_EMPTY:
    case DEVPROP_TYPE_NULL:
        WriteStdOut(TEXT("\n"));
        break;
    case DEVPROP_TYPE_SBYTE:
    case DEVPROP_TYPE_BYTE:
        WriteStdOut(TEXT("0x%02x\n"), value[0]);
        break;
    case DEVPROP_TYPE_INT16:
        WriteStdOut(TEXT("%d\n"), *(SHORT *)value);
        break;
    case DEVPROP_TYPE_UINT16:
        WriteStdOut(TEXT("%u\n"), *(USHORT *)value);
        break;
    case DEVPROP_TYPE_INT32:
        WriteStdOut(TEXT("%ld\n"), *(LONG *)value);
        break;
    case DEVPROP_TYPE_UINT32:
        WriteStdOut(TEXT("%lu\n"), *(ULONG *)value);
        break;
    case DEVPROP_TYPE_INT64:
        WriteStdOut(TEXT("%lld\n"), *(LONG64 *)value);
        break;
    case DEVPROP_TYPE_UINT64:
        WriteStdOut(TEXT("%llu\n"), *(ULONG64 *)value);
        break;
    case DEVPROP_TYPE_FLOAT:
        WriteStdOut(TEXT("%f\n"), *(FLOAT *)value);
        break;
    case DEVPROP_TYPE_DOUBLE:
        WriteStdOut(TEXT("%lf\n"), *(double *)value);
        break;
    case DEVPROP_TYPE_DECIMAL:
        WriteStdErr(TEXT("Not support property type '%ld'\n"), type);
        break;
    case DEVPROP_TYPE_GUID:
        GUID id = *(GUID *)value;
        WriteStdOut(TEXT("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\n"), id.Data1, id.Data2, id.Data3,
                    id.Data4[0], id.Data4[1], id.Data4[2], id.Data4[3], id.Data4[4], id.Data4[5], id.Data4[6],
                    id.Data4[7]);
        break;
    case DEVPROP_TYPE_CURRENCY:
        WriteStdErr(TEXT("Not support property type '%ld'\n"), type);
        break;
    case DEVPROP_TYPE_DATE:
        WriteStdOut(TEXT("%lf\n"), *(double *)value);
        break;
    case DEVPROP_TYPE_FILETIME:
        SYSTEMTIME sysTime = {0};
        if (!FileTimeToSystemTime((FILETIME *)value, &sysTime))
        {
            return FALSE;
        }
        WriteStdOut(TEXT("%u/%u/%u %u:%u:%u.%u\n"), sysTime.wYear, sysTime.wMonth, sysTime.wDay, sysTime.wHour,
                    sysTime.wMinute, sysTime.wSecond, sysTime.wMilliseconds);
        break;
    case DEVPROP_TYPE_BOOLEAN:
        WriteStdOut(TEXT("%u\n"), *(BYTE *)value);
        break;
    case DEVPROP_TYPE_STRING:
        LPSTR mb = NULL;
        if (!WideToMB(heap, (LPCWCH)value, &mb))
        {
            return FALSE;
        }

        WriteStdOut(TEXT("%s\n"), mb);

        HeapFree(heap, 0, mb);
        break;
    case DEVPROP_TYPE_STRING_LIST:
        // TODO:
        break;
    case DEVPROP_TYPE_SECURITY_DESCRIPTOR:
    case DEVPROP_TYPE_SECURITY_DESCRIPTOR_STRING:
    case DEVPROP_TYPE_DEVPROPKEY:
    case DEVPROP_TYPE_DEVPROPTYPE:
        WriteStdErr(TEXT("Not support property type '%ld'\n"), type);
        break;
    case DEVPROP_TYPE_BINARY:
        for (ULONG i = 0; i < size; i++)
        {
            WriteStdOut(TEXT("0x%02x"), value[i]);
        }
        WriteStdOut(TEXT("\n"));
        break;
    case DEVPROP_TYPE_ERROR:
        WriteStdOut(TEXT("%ld\n"), *(LONG *)value);
        break;
    case DEVPROP_TYPE_NTSTATUS:
        WriteStdOut(TEXT("%ld\n"), *(LONG *)value);
        break;
    case DEVPROP_TYPE_STRING_INDIRECT:
        // TODO:
        break;
    default:
        WriteStdErr(TEXT("Not found property type '%ld'\n"), type);
        break;
    }

    return TRUE;
}
