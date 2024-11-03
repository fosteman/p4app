#include <core.p4>
#include <v1model.p4>

#include "header.p4"
#include "parser.p4"

// Egress control block
control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("rewrite_mac") action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }

    @name("drop") action drop() {
        mark_to_drop(standard_metadata);
    }

    @name("send_frame") table send_frame {
        actions = {
            rewrite_mac;
            drop;
            NoAction;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        size = 256;
        default_action = drop(); // Set drop as the default action
    }

    apply {
        if (hdr.ipv4.isValid()) {
            send_frame.apply();
        }
    }
}

// Ingress control block
control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    // Define a register to count packets forwarded
    register<bit<32>>(1) forward_count_register;

    @name("drop") action drop() {
        mark_to_drop(standard_metadata);
    }

    action increment_counter() {
        bit<32> forward_count;
        forward_count_register.read(forward_count, 0);
        forward_count_register.write(0, forward_count + 1);
    }

    @name("set_nhop") action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        meta.ingress_metadata.nhop_ipv4 = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1; // Decrement TTL
        increment_counter();
    }

    @name("set_dmac") action set_dmac(bit<48> dmac) {
        hdr.ethernet.dstAddr = dmac;
    }

    @name("ipv4_lpm") table ipv4_lpm {
        actions = {
            drop;
            set_nhop;
            NoAction;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
        default_action = drop(); // Set drop as the default action
    }

    @name("forward") table forward {
        actions = {
            set_dmac;
            drop;
            NoAction;
        }
        key = {
            meta.ingress_metadata.nhop_ipv4: exact;
        }
        size = 512;
        default_action = drop(); // Set drop as the default action
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            forward.apply();
        }
    }
}

// Main control pipeline
V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;