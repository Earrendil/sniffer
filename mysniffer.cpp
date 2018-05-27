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

int main() {
    print_all_interfaces();
    //try{
    Sniffer sniffer("ens33");
    sniffer.sniff_loop(callback);
   // } catch (std::exception e) {
    //    e.what();
    //}
}