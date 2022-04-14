#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_UDP = 0x11;
const bit<8> TYPE_TCP = 0x06;

const bit<16> udpDstPort = 1701;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


const ip4Addr_t currentSwitchIP = 0x84442494; //132.68.36.148
const ip4Addr_t otherSwitchIP = 0x84442569; //132.68.37.105
const ip4Addr_t IPMask = 0xFFFFF000; // IPMask = 255.255.255.0

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header tcp_t {

    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  cntl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;

}


struct metadata {
    /* empty */
    
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    ethernet_t   ethernet_2;
    ipv4_t       ipv4_2;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.srcAddr){
            otherSwitchIP: parse_check_tunnel_valid;
            default: accept;
        }
    }

    state parse_check_tunnel_valid {
        transition select(hdr.ipv4.protocol){
            TYPE_UDP: parse_check_udp_port;
            default: reject;
        }
    }

    state parse_check_udp_port {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort){
            udpDstPort: parse_tunnel;
            default: reject;
        }

    }

    state parse_tunnel {
        packet.extract(hdr.ethernet_2);
        packet.extract(hdr.ipv4_2);
        transition accept;
    }
    
 
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}


control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {


    action drop() {
        mark_to_drop( standard_metadata );
        exit;
    }

    action bcast(){
        standard_metadata.egress_port = 9w100; // Broadcast port
    }

    action forward_local() {
        // todo: change this to the wifi port number
        standard_metadata.egress_port = 9w100; // Broadcast port

    }
    
    action forward_external() {
        // todo: change this to the ethernet port number
        standard_metadata.egress_port = 9w100; // Broadcast port

    }

    action create_tunnel(){
        // todo: change this to the ethernet port number
        standard_metadata.egress_port = 9w100; // Broadcast port
        hdr.ethernet_2 = hdr.ethernet;
        hdr.ipv4_2 = hdr.ipv4;

        hdr.ipv4_2.srcAddr = currentSwitchIP;
        hdr.ipv4_2.dstAddr = otherSwitchIP;
        hdr.ipv4_2.protocol = 17;

        //todo: fill more fields if neccesary.. calculate length?

        hdr.udp.dstPort = udpDstPort;
        hdr.udp.srcPort = udpDstPort;
        hdr.udp.length = 0; 
        hdr.udp.checksum = 0; 

    }

    action decode_tunnel(){
        standard_metadata.egress_port = 9w100; // Broadcast port

    }


    apply {
        if(hdr.ipv4.srcAddr == otherSwitchIP){
            decode_tunnel();
        }
        else{
            forward_local();
        }

        if((hdr.ipv4.dstAddr ^ IPMask) == (otherSwitchIP ^ IPMask)){
            create_tunnel();
        }
        else{
            forward_external();
        }
    }

}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {

        // The packet is of type IPV4
        if(hdr.ethernet.etherType == TYPE_IPV4){
            // The packet came from the other switch
            if(hdr.ipv4.srcAddr == otherSwitchIP){
                packet.emit(hdr.ethernet_2);
                packet.emit(hdr.ipv4_2);
            }
            else{
                // The packet destination is the other switch
                if((hdr.ipv4.dstAddr ^ IPMask) == (otherSwitchIP ^ IPMask)){
                    packet.emit(hdr.ethernet_2);
                    packet.emit(hdr.ipv4_2);
                    packet.emit(hdr.udp);
                    packet.emit(hdr.ethernet);
                    packet.emit(hdr.ipv4);
                }
                else{
                    // The packet is a normal IPv4 packet that does not involve the other switch
                    packet.emit(hdr.ethernet);
                    packet.emit(hdr.ipv4);
                }
            }

        }
        else{
            // The packet type is not IPV4
            packet.emit(hdr.ethernet);
        }



    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;