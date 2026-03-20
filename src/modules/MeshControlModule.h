#pragma once
#include "mesh/ProtobufModule.h"
#include "mesh/generated/meshtastic/mesh_control.pb.h"
#include "mesh/generated/meshtastic/config.pb.h"
#include <SHA256.h>

class MeshControlModule : public ProtobufModule<meshtastic_MeshControlPacket>
{
  public:
    MeshControlModule();

  protected:
    virtual bool handleReceivedProtobuf(const meshtastic_MeshPacket &mp, meshtastic_MeshControlPacket *p) override;

  private:
    uint32_t lastAcceptedSeqNum = 0;
    uint32_t lastAcceptTime = 0;

    bool validateHMAC(const meshtastic_MeshControlPacket *p);
    bool checkReplayProtection(const meshtastic_MeshControlPacket *p);
    void applySettings(const meshtastic_MeshControlPacket *p);
    void notifyUser(const char *message);
};

extern MeshControlModule *meshControlModule;
