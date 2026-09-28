import veins.modules.messages.BaseFrame1609_4;

namespace veins;

packet QuicFecDatagram extends BaseFrame1609_4 {
    int srcNode = -1;
    int dstNode = -1;
    uint8_t payload[];
}
