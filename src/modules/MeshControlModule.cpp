#include "MeshControlModule.h"
#include "mesh/Channels.h"
#include "mesh/NodeDB.h"
#include "mesh/Router.h"
#include "modules/AdminModule.h"
#include <Arduino.h>

MeshControlModule *meshControlModule;

MeshControlModule::MeshControlModule() : ProtobufModule("MeshControl", meshtastic_PortNum_MESH_CONTROL_APP, meshtastic_MeshControlPacket_fields)
{
    isPromiscuous = true;
}

bool MeshControlModule::handleReceivedProtobuf(const meshtastic_MeshPacket &mp, meshtastic_MeshControlPacket *p)
{
    if (p == nullptr) {
        return false;
    }

    if (config.mesh_control.control_key.size == 0) {
        LOG_DEBUG("MeshControl: No control_key configured, ignoring packet");
        return false;
    }

    LOG_INFO("MeshControl: Received packet from=0x%08x, seq_num=%u, mesh_name='%s'",
             mp.from, p->seq_num, p->mesh_name);

    if (!validateHMAC(p)) {
        LOG_WARN("MeshControl: HMAC validation failed from=0x%08x", mp.from);
        return true;
    }

    if (!checkReplayProtection(p)) {
        LOG_WARN("MeshControl: Replay attack detected, seq_num=%u from=0x%08x", p->seq_num, mp.from);
        return true;
    }

    if (!p->has_settings) {
        LOG_DEBUG("MeshControl: Packet has no settings to apply");
        return true;
    }

    applySettings(p);
    return true;
}

bool MeshControlModule::validateHMAC(const meshtastic_MeshControlPacket *p)
{
    if (config.mesh_control.control_key.size != 32) {
        LOG_WARN("MeshControl: Invalid control_key size: %d", config.mesh_control.control_key.size);
        return false;
    }

    meshtastic_MeshControlPacket packetCopy = *p;
    memset(&packetCopy.hmac, 0, sizeof(packetCopy.hmac));

    uint8_t computedHmac[32];
    SHA256 hmac;
    hmac.resetHMAC(config.mesh_control.control_key.bytes, config.mesh_control.control_key.size);
    hmac.update(&packetCopy, sizeof(meshtastic_MeshControlPacket));
    hmac.finalizeHMAC(config.mesh_control.control_key.bytes, config.mesh_control.control_key.size, computedHmac, 16);

    if (memcmp(p->hmac.bytes, computedHmac, 16) != 0) {
        LOG_WARN("MeshControl: HMAC mismatch");
        for (int i = 0; i < 16; i++) {
            LOG_DEBUG("MeshControl: expected[%d]=%02x, got[%d]=%02x", 
                      i, p->hmac.bytes[i], i, computedHmac[i]);
        }
        return false;
    }

    LOG_DEBUG("MeshControl: HMAC validated successfully");
    return true;
}

bool MeshControlModule::checkReplayProtection(const meshtastic_MeshControlPacket *p)
{
    uint32_t now = millis() / 1000;

    if (p->seq_num <= lastAcceptedSeqNum) {
        LOG_WARN("MeshControl: seq_num %u is not greater than last accepted %u",
                 p->seq_num, lastAcceptedSeqNum);
        return false;
    }

    uint32_t minInterval = config.mesh_control.min_interval_secs;
    if (minInterval == 0) {
        minInterval = 60;
    }

    if (now - lastAcceptTime < minInterval && lastAcceptTime > 0) {
        LOG_WARN("MeshControl: min_interval_secs not elapsed (now=%u, last=%u, min=%u)",
                 now, lastAcceptTime, minInterval);
        return false;
    }

    lastAcceptedSeqNum = p->seq_num;
    lastAcceptTime = now;

    LOG_DEBUG("MeshControl: Replay check passed, seq_num=%u", p->seq_num);
    return true;
}

void MeshControlModule::applySettings(const meshtastic_MeshControlPacket *p)
{
    const meshtastic_MeshControlSettings *settings = &p->settings;

    LOG_INFO("MeshControl: Applying settings from mesh_name='%s'", p->mesh_name);

    switch (config.mesh_control.accept_policy) {
    case meshtastic_Config_MeshControlConfig_AcceptPolicy_AUTO:
        LOG_INFO("MeshControl: AUTO policy - applying settings directly");
        break;
    case meshtastic_Config_MeshControlConfig_AcceptPolicy_PROMPT:
        LOG_INFO("MeshControl: PROMPT policy - notifying user");
        notifyUser("MeshControl: Settings received from administrator");
        break;
    case meshtastic_Config_MeshControlConfig_AcceptPolicy_DISABLED:
    default:
        LOG_INFO("MeshControl: DISABLED policy - not applying");
        return;
    }

    if (settings->has_modem_preset) {
        LOG_INFO("MeshControl: Setting modem_preset=%d", settings->modem_preset);
        config.lora.modem_preset = settings->modem_preset;
        config.has_lora = true;
    }

    if (settings->has_override_frequency && settings->override_frequency > 0) {
        LOG_INFO("MeshControl: Setting override_frequency=%.1f MHz", settings->override_frequency);
        config.lora.override_frequency = settings->override_frequency;
        config.has_lora = true;
    }

    if (settings->has_channel_num) {
        LOG_INFO("MeshControl: Setting channel_num=%u", settings->channel_num);
        config.lora.channel_num = settings->channel_num;
        config.has_lora = true;
    }

    if (settings->has_hop_limit) {
        LOG_INFO("MeshControl: Setting hop_limit=%u", settings->hop_limit);
        config.lora.hop_limit = settings->hop_limit;
        config.has_lora = true;
    }

    if (settings->has_broadcast_hop_limit) {
        LOG_INFO("MeshControl: Setting broadcast_hop_limit=%u", settings->broadcast_hop_limit);
        config.lora.broadcast_hop_limit = settings->broadcast_hop_limit;
        config.has_lora = true;
    }

    if (settings->has_position_broadcast_secs) {
        LOG_INFO("MeshControl: Setting position_broadcast_secs=%u", settings->position_broadcast_secs);
        config.position.position_broadcast_secs = settings->position_broadcast_secs;
        config.has_position = true;
    }

    if (settings->has_device_telemetry_interval) {
        LOG_INFO("MeshControl: Setting device_telemetry_interval=%u", settings->device_telemetry_interval);
        moduleConfig.telemetry.device_update_interval = settings->device_telemetry_interval;
        moduleConfig.has_telemetry = true;
    }

    if (settings->has_node_info_broadcast_secs) {
        LOG_INFO("MeshControl: Setting node_info_broadcast_secs=%u", settings->node_info_broadcast_secs);
        config.device.node_info_broadcast_secs = settings->node_info_broadcast_secs;
        config.has_device = true;
    }

    nodeDB->saveToDisk();
    LOG_INFO("MeshControl: Settings applied and saved");
}

void MeshControlModule::notifyUser(const char *message)
{
    LOG_INFO("MeshControl: %s", message);
}
