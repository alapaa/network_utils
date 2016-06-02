#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <linux/errqueue.h>
#include <arpa/inet.h>
#include <cstring> // memset()
#include <string>
#include <system_error>
#include <iostream>

using std::string;
using std::cout;

/**
 * Prerequisite: setsockopt for receiving socket errors on sock errque set
 * before e.g. sendto() was called. This function just harvests any errors.
 */
void receive_icmp_error(bool v6, int sock)
{
    /* Handle receving ICMP Errors */
    const int BUFFER_MAX_SIZE = 1024;
    char buffer[BUFFER_MAX_SIZE];
    struct iovec iov;                       /* Data array */
    struct msghdr msg;                      /* Message header */
    struct cmsghdr *cmsg;                   /* Control related data */
    struct sock_extended_err *sock_err;     /* Struct describing the error */
    struct icmphdr icmph;                   /* ICMP header */
    struct sockaddr_in remote4;
    struct sockaddr_in6 remote6;
    int result;

    int msg_count = 0;
    for (;;)
    {
        iov.iov_base = &icmph;
        iov.iov_len = sizeof(icmph);
        if (v6)
        {
            msg.msg_name = (void*)&remote6;
            msg.msg_namelen = sizeof(remote6);
        }
        else
        {
            msg.msg_name = (void*)&remote4;
            msg.msg_namelen = sizeof(remote4);
        }
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_flags = 0;
        msg.msg_control = buffer;
        msg.msg_controllen = sizeof(buffer);
        /* Receiving errors flog is set */
        result = recvmsg(sock, &msg, MSG_ERRQUEUE);
        if (result == -1)
        {
            cout << '.';
            sleep(1);
            continue;
        }
        cout << '\n';
        /* Control messages are always accessed via some macros
         * http://www.kernel.org/doc/man-pages/online/pages/man3/cmsg.3.html
         */
        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
        {
            cout << "Got msg on error queue\n";
            /* Ip level */
            if ( (cmsg->cmsg_level == SOL_IP || cmsg->cmsg_level == SOL_IPV6) &&
                 (cmsg->cmsg_type == IP_RECVERR || cmsg->cmsg_type == IPV6_RECVERR))
            {

                fprintf(stderr, "We got IP(v4/v6)_RECVERR message\n");
                sock_err = (struct sock_extended_err*)CMSG_DATA(cmsg);
                if (sock_err &&
                    (sock_err->ee_origin == SO_EE_ORIGIN_ICMP || sock_err->ee_origin == SO_EE_ORIGIN_ICMP6))
                {

                    cout << "ICMP error!\n";
                    /* Handle ICMP errors types */
                    switch (sock_err->ee_type)
                    {
                        case ICMP_DEST_UNREACH:
                            cout << "Destination unreachable, ";
                            switch (sock_err->ee_code)
                            {
                            case ICMP_NET_UNREACH:
                                cout << ", network unreachable\n";
                                break;
                            case    ICMP_HOST_UNREACH:
                                cout << "host unreachable\n";
                                break;
                            case ICMP_PORT_UNREACH:
                                cout << "port unreachable\n";
                                break;
                            case ICMP_NET_UNKNOWN:
                                cout << "unknown network\n";
                                break;
                            case ICMP_HOST_UNKNOWN:
                                cout << "unknown Host\n";
                                break;
                            case ICMP_FRAG_NEEDED:
                                cout << "fragmentation needed, mtu " <<
                                    sock_err->ee_info << '\n';
                                break;
                            default:
                                cout << "code=" << sock_err->ee_code << '\n';
                                break;
                            }
                        break;
                        case ICMP6_DST_UNREACH:
                            cout << "Destination unreachable, ";
                            switch (sock_err->ee_code)
                            {
                                case ICMP6_DST_UNREACH_NOROUTE:
                                    cout << "no route to destination\n";
                                    break;
                                case ICMP6_DST_UNREACH_ADMIN:
                                    cout << "communication with destination administratively prohibited\n";
                                    break;
                                case ICMP6_DST_UNREACH_BEYONDSCOPE:
                                    cout << "beyond scope of source address\n";
                                    break;
                                case ICMP6_DST_UNREACH_ADDR:
                                    cout << "address unreachable\n";
                                    break;
                                case ICMP6_DST_UNREACH_NOPORT:
                                    cout << "bad port\n";
                                    break;
                                default:
                                    cout << "code " << sock_err->ee_code;
                                    break;
                            }
                            break;
                        case ICMP6_PACKET_TOO_BIG:
                            cout << "Packet Too Big Error, mtu " <<
                            sock_err->ee_info << '\n';
                            break;
                        default:
                            // More errors: http://lxr.linux.no/linux+v3.5/include/linux/icmp.h#L39
                            cout << "Other ICMP error\n";
                            break;

                    }
                }
            }
        }
    }
}

void probe_and_receive_icmp(bool v6, string addrstr, int pkt_sz, in_port_t port)
{
    int sock;
    int result;

    cout << "Target addr: " << addrstr << ", packet size " << pkt_sz << '\n';

    int domain = v6 ? AF_INET6 : AF_INET;
    sock = socket(domain, SOCK_DGRAM, 0);
    if (sock == -1)
    {
        throw std::system_error(errno, std::system_category());
    }

    int val;
    if (v6)
    {
        val = IPV6_PMTUDISC_DO;
        result = setsockopt(sock, SOL_IPV6, IPV6_MTU_DISCOVER, &val, sizeof(val));
    }
    else
    {
        val = IP_PMTUDISC_DO;
        result = setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
    }
    if (result == -1)
    {
        throw std::system_error(errno, std::system_category());
    }

    /* Set the option, so we can receive errors */
    val = 1;
    result = setsockopt(sock, SOL_IP, IP_RECVERR,(char*)&val, sizeof(val));
    if (result == -1)
    {
        throw std::system_error(errno, std::system_category());
    }

    if (v6)
    {
        val = 1;
        result = setsockopt(sock, SOL_IPV6, IPV6_RECVERR,(char*)&val, sizeof(val));
        if (result == -1)
        {
            throw std::system_error(errno, std::system_category());
        }
    }

    unsigned char addrbuf[sizeof(struct in6_addr)];

    result = inet_pton(domain, addrstr.c_str(), addrbuf);
    if (result <= 0) {
        if (result == 0)
            throw std::runtime_error("Address not in presentation format");
        else
            throw std::system_error(errno, std::system_category());
    }

    struct sockaddr_in6 addr6;
    struct sockaddr_in addr4;
    sockaddr *addr = nullptr;
    if (v6)
    {
        memset((char *) &addr6, 0, sizeof(addr6));
        addr6.sin6_family = domain;
        addr6.sin6_port = htons(port);
        memcpy(&addr6.sin6_addr, addrbuf, sizeof(addr6.sin6_addr));
        addr = (sockaddr*)&addr6;
    }
    else
    {
        memset((char *) &addr4, 0, sizeof(addr4));
        addr4.sin_family = domain;
        addr4.sin_port = htons(port);
        memcpy(&addr4.sin_addr, addrbuf, sizeof(addr4.sin_addr));
        addr = (sockaddr*)&addr4;
    }

    int udp_header_sz = v6 ? 48 : 28;
    int buf_sz = pkt_sz - udp_header_sz;
    char buf[buf_sz];
    cout << "Sending msg, payload size " << buf_sz << '\n';
    result = sendto(sock, buf, buf_sz, 0, addr, v6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in));
    if (result == -1)
    {
        throw std::system_error(errno, std::system_category());
    }

    receive_icmp_error(v6, sock);

}

int main(int argc, char* argv[])
{
    if (argc != 5) {
        cout << "Usage: recv_icmp <v4/v6> <ip addr> <packet sz> <udp port>\n";
        exit(1);
    }

    string ipver(argv[1]);
    bool v6 = (ipver == "v6") ? true : false;
    string ip_addr(argv[2]);
    int pkt_sz = stoi(string(argv[3]));
    in_port_t port = stoi(string(argv[4]));

    probe_and_receive_icmp(v6, ip_addr, pkt_sz, port);

    return 0;
}
