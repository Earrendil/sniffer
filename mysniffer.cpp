#include <iostream>
#include <tins/tins.h>

using namespace Tins;
using namespace std;

bool callback(const PDU &pdu) {
    // Find the IP layer
    const IP &ip = pdu.rfind_pdu<IP>(); 
    cout << ip.src_addr() << " -> " 
         << ip.dst_addr() << endl;
    // Find the TCP layer
    //const TCP &tcp = pdu.rfind_pdu<TCP>(); 
    //cout << ip.src_addr() << ':' << tcp.sport() << " -> " 
    //     << ip.dst_addr() << ':' << tcp.dport() << endl;
    return true;
}

void print_all_interfaces() {

    vector<NetworkInterface> interfaces = NetworkInterface::all();

    for (const NetworkInterface& iface : interfaces) {
        cout << "Interface name: " << iface.name();
        wcout << " (" << iface.friendly_name() << ")" << endl;
    }
}

void save_pockets_to_pcap(std::string filename, std::vector<PDU*> packets) {
    PacketWriter writer(filename, DataLinkType<EthernetII>());
    writer.write(packets.begin(), packets.end());
   // for (const auto& pdu : packets) {
        // Is there an IP PDU somewhere?
      //  if (pdu->find_pdu<IP>()) {
            // Just print timestamp's seconds and IP source address
     // std::cout << "At: " << pdu->timestamp().seconds()
            //        << " - " << pdu->rfind_pdu<IP>().src_addr() 
          //          << std::endl;
      //  }
    
}

std::vector<PDU*> sniff_packets(u_int num_of_pockets) {
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    
    Sniffer sniffer("ens33", config);
    IPv4Address filter1 = "192.168.174.1";
    IPv4Address filter2 = "192.168.174.128";
    //sniffer.sniff_loop(callback);
    std::vector<PDU*> packets;
    while (packets.size() != num_of_pockets) {
        // next_packet returns a PtrPacket, which can be implicitly converted to Packet.
        PDU* pdu = sniffer.next_packet();
        try{
            const IP &ip = pdu->rfind_pdu<IP>(); 
            if (ip.src_addr() !=  filter1 && ip.src_addr() != filter2){
              packets.push_back(pdu);
                cout << ip.src_addr() << " -> " 
                << ip.dst_addr() << endl;  
            }
            
         } catch (std::exception e) {
             e.what();
         }
         delete pdu;
    }
    return packets;
    /*
    for (int i=0; i<num_of_pockets; ++i) {
        cout<<"1"<<endl;
        PDU *pdu = sniffer.next_packet();
         cout<<"2"<<endl;
         try{
            const IP &ip = pdu->rfind_pdu<IP>(); 
            cout<<"3"<<endl;
            cout << ip.src_addr() << " -> " 
            << ip.dst_addr() << endl;
         } catch (std::exception e) {
             e.what();
         }
        delete pdu;
    }
    */
}

int main() {
    print_all_interfaces();
    std::vector<PDU*> packets = sniff_packets(100);
    save_pockets_to_pcap("log.pcap", packets);
    //try{
    
   // } catch (std::exception e) {packets
    //    e.what();
    //}
}