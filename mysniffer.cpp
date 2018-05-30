#include <iostream>
#include <fstream>
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

void save_pockets_to_pcap(const std::string& filename, std::vector<PDU*> packets) {
    //void save_pockets_to_pcap(const std::string& filename, std::vector<Packet> packets) {
    ofstream pcap_file (filename);
    pcap_file.close();
    
    PacketWriter writer(filename, DataLinkType<EthernetII>());
    //cout<<"OK4"<<endl;
    //out<<writer.ETH2<<endl;
    for (const auto& packet : packets) {
       // cout<<"rpzed"<<endl;
        writer.write(packet);
       // cout<<"po"<<endl;
    }
    //writer.write(packets.begin(), packets.end());
   // cout<<"OK5"<<endl;
   // for (const auto& pdu : packets) {
        // Is there an IP PDU somewhere?
      //  if (pdu->find_pdu<IP>()) {
            // Just print timestamp's seconds and IP source address
     // std::cout << "At: " << pdu->timestamp().seconds()
            //        << " - " << pdu->rfind_pdu<IP>().src_addr() 
          //          << std::endl;
      //  }
    
}

bool is_filtered(IP ip) {
    std::vector<std::string> filters;
    filters.push_back("192.168.174.1");
    filters.push_back("192.168.174.128");
    filters.push_back("169.254.96.213");
    filters.push_back("169.254.246.234");
    filters.push_back("239.255.255.250");
    filters.push_back("0.0.0.0");
    filters.push_back("255.255.255.255");
    filters.push_back("169.254.102.13");
    filters.push_back("169.254.205.71");
    filters.push_back("224.0.0.251");
    filters.push_back("224.0.0.22");

    for (const auto& filter : filters) {
        if (ip.src_addr() ==  IPv4Address(filter) 
            || ip.dst_addr() == IPv4Address(filter)){
            return true;
        }
    }
    return false;       
}

std::vector<PDU*> sniff_packets(u_int num_of_pockets) {
//std::vector<Packet> sniff_packets(u_int num_of_pockets) {
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    
    Sniffer sniffer("ens33", config);
  //  IPv4Address filter1 = "192.168.174.1";
  //  IPv4Address filter2 = "192.168.174.128";
    //sniffer.sniff_loop(callback);
    std::vector<PDU*> packets;
    //std::vector<Packet> packets;
    while (packets.size() != num_of_pockets) {
        // next_packet returns a PtrPacket, which can be implicitly converted to Packet.
        PDU* pdu = sniffer.next_packet();
        //Packet pdu = sniffer.next_packet();
        try{
            //const IP &ip = pdu.pdu()->rfind_pdu<IP>(); 
            const IP &ip = pdu->rfind_pdu<IP>(); 
            //if (ip.src_addr() !=  filter1 && ip.src_addr() != filter2){
            
            if (!is_filtered(ip)) {
                packets.push_back(pdu);
                cout << ip.src_addr() << " -> " 
                << ip.dst_addr() << endl;  
            }
            
         } catch (std::exception e) {
             e.what();
         }
        // cout<<"OK1"<<endl;
         //delete pdu;
    }
   // cout<<"OK2"<<endl;
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
    std::vector<PDU*> packets = sniff_packets(2000);
    //std::vector<Packet> packets = sniff_packets(5);
    //cout<<"OK3"<<endl;
    save_pockets_to_pcap("log.pcap", packets);
    //cout<<"OK5"<<endl;
    //try{
    
   // } catch (std::exception e) {packets
    //    e.what();
    //}
}