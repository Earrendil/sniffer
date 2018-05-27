#include <iostream>
#include <tins/tins.h>

using namespace Tins;
using namespace std;

bool callback(const PDU &pdu) {
    // Find the IP layer
    const IP &ip = pdu.rfind_pdu<IP>(); 
    // Find the TCP layer
    const TCP &tcp = pdu.rfind_pdu<TCP>(); 
    cout << ip.src_addr() << ':' << tcp.sport() << " -> " 
         << ip.dst_addr() << ':' << tcp.dport() << endl;
    return true;
}

void print_all_interfaces() {

    std::cout<<"Hello world!"<<std::endl;
    vector<NetworkInterface> interfaces = NetworkInterface::all();

    for (const NetworkInterface& iface : interfaces) {
        cout << "Interface name: " << iface.name();
        wcout << " (" << iface.friendly_name() << ")" << endl;
    }
}

int main() {
    print_all_interfaces();
    Sniffer("eth0").sniff_loop(callback);
}