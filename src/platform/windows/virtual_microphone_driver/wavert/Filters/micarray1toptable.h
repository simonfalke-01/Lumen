/*++

Copyright (c) Microsoft Corporation All Rights Reserved

Module Name:

    micarray1toptable.h

Abstract:

    Declaration of topology tables for the mic array.

--*/

#ifndef _SIMPLEAUDIOSAMPLE_MICARRAY1TOPTABLE_H_
#define _SIMPLEAUDIOSAMPLE_MICARRAY1TOPTABLE_H_

//
// {109DB539-1977-4C12-88A2-F22BDAC5AB13}
DEFINE_GUID(MICARRAY1_CUSTOM_NAME,
    0x109db539, 0x1977, 0x4c12, 0x88, 0xa2, 0xf2, 0x2b, 0xda, 0xc5, 0xab, 0x13);

//=============================================================================
static
KSDATARANGE MicArray1TopoPinDataRangesBridge[] =
{
 {
   sizeof(KSDATARANGE),
   0,
   0,
   0,
   STATICGUIDOF(KSDATAFORMAT_TYPE_AUDIO),
   STATICGUIDOF(KSDATAFORMAT_SUBTYPE_ANALOG),
   STATICGUIDOF(KSDATAFORMAT_SPECIFIER_NONE)
 }
};

//=============================================================================
static
PKSDATARANGE MicArray1TopoPinDataRangePointersBridge[] =
{
  &MicArray1TopoPinDataRangesBridge[0]
};

//=============================================================================
static
PCPIN_DESCRIPTOR MicArray1TopoMiniportPins[] =
{
    // KSPIN_TOPO_MIC_ELEMENTS
    {
      0,
      0,
      0,                                              // InstanceCount
      NULL,                                           // AutomationTable
      {                                               // KsPinDescriptor
        0,                                            // InterfacesCount
        NULL,                                         // Interfaces
        0,                                            // MediumsCount
        NULL,                                         // Mediums
        SIZEOF_ARRAY(MicArray1TopoPinDataRangePointersBridge),     // DataRangesCount
        MicArray1TopoPinDataRangePointersBridge,                   // DataRanges
        KSPIN_DATAFLOW_IN,                            // DataFlow
        KSPIN_COMMUNICATION_NONE,                     // Communication
        &KSNODETYPE_MICROPHONE,                       // Category
        &MICARRAY1_CUSTOM_NAME,                       // Name
        0                                             // Reserved
      }
    },

    // KSPIN_TOPO_BRIDGE
    {
      0,
      0,
      0,                                              // InstanceCount
      NULL,                                           // AutomationTable
      {                                               // KsPinDescriptor
        0,                                            // InterfacesCount
        NULL,                                         // Interfaces
        0,                                            // MediumsCount
        NULL,                                         // Mediums
        SIZEOF_ARRAY(MicArray1TopoPinDataRangePointersBridge),     // DataRangesCount
        MicArray1TopoPinDataRangePointersBridge,                   // DataRanges
        KSPIN_DATAFLOW_OUT,                           // DataFlow
        KSPIN_COMMUNICATION_NONE,                     // Communication
        &KSCATEGORY_AUDIO,                            // Category
        NULL,                                         // Name
        0                                             // Reserved
      }
    }
};

//=============================================================================
static
PCPROPERTY_ITEM MicArray1PropertiesVolume[] =
{
    {
    &KSPROPSETID_Audio,
    KSPROPERTY_AUDIO_VOLUMELEVEL,
    KSPROPERTY_TYPE_GET | KSPROPERTY_TYPE_SET | KSPROPERTY_TYPE_BASICSUPPORT,
    PropertyHandler_MicArrayTopology
    }
};

DEFINE_PCAUTOMATION_TABLE_PROP(AutomationMicArray1Volume, MicArray1PropertiesVolume);

//=============================================================================
static
PCPROPERTY_ITEM MicArray1PropertiesMute[] =
{
  {
    &KSPROPSETID_Audio,
    KSPROPERTY_AUDIO_MUTE,
    KSPROPERTY_TYPE_GET | KSPROPERTY_TYPE_SET | KSPROPERTY_TYPE_BASICSUPPORT,
    PropertyHandler_MicArrayTopology
  }
};

DEFINE_PCAUTOMATION_TABLE_PROP(AutomationMicArray1Mute, MicArray1PropertiesMute);

//=============================================================================
static
PCNODE_DESCRIPTOR MicArray1TopologyNodes[] =
{
    // KSNODE_TOPO_VOLUME
    {
      0,                              // Flags
      &AutomationMicArray1Volume,     // AutomationTable
      &KSNODETYPE_VOLUME,             // Type
      &KSAUDFNAME_MIC_VOLUME          // Name
    },
    // KSNODE_TOPO_MUTE
    {
      0,                              // Flags
      &AutomationMicArray1Mute,       // AutomationTable
      &KSNODETYPE_MUTE,               // Type
      &KSAUDFNAME_MIC_MUTE            // Name
    }
};

C_ASSERT(KSNODE_TOPO_VOLUME == 0);
C_ASSERT(KSNODE_TOPO_MUTE == 1);

static
PCCONNECTION_DESCRIPTOR MicArray1TopoMiniportConnections[] =
{
    //  FromNode,                 FromPin,                    ToNode,                 ToPin
    {   PCFILTER_NODE,            KSPIN_TOPO_MIC_ELEMENTS,    KSNODE_TOPO_VOLUME,     1 },
    {   KSNODE_TOPO_VOLUME,       0,                          KSNODE_TOPO_MUTE,       1 },
    {   KSNODE_TOPO_MUTE,         0,                          PCFILTER_NODE,          KSPIN_TOPO_BRIDGE }
};



//=============================================================================
//=============================================================================
static
PCFILTER_DESCRIPTOR MicArray1TopoMiniportFilterDescriptor =
{
  0,                                            // Version
  NULL,                                         // AutomationTable
  sizeof(PCPIN_DESCRIPTOR),                     // PinSize
  SIZEOF_ARRAY(MicArray1TopoMiniportPins),      // PinCount
  MicArray1TopoMiniportPins,                    // Pins
  sizeof(PCNODE_DESCRIPTOR),                    // NodeSize
  SIZEOF_ARRAY(MicArray1TopologyNodes),         // NodeCount
  MicArray1TopologyNodes,                       // Nodes
  SIZEOF_ARRAY(MicArray1TopoMiniportConnections),// ConnectionCount
  MicArray1TopoMiniportConnections,             // Connections
  0,                                            // CategoryCount
  NULL                                          // Categories
};

#endif // _SIMPLEAUDIOSAMPLE_MICARRAY1TOPTABLE_H_
