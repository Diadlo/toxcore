/* network.c
 *
 * Functions for the core networking.
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

// TODO: remove comment
//#if defined(_WIN32) && _WIN32_WINNT >= _WIN32_WINNT_WINXP
#define _WIN32_WINNT  0x501

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "network.h"

#include "../toxcore/logger.h"
#include "../toxcore/util.h"


static const char *inet_ntop(sa_family_t family, const void *addr, char *buf, size_t bufsize)
{
    if (family == AF_INET) {
        struct sockaddr_in saddr;
        memset(&saddr, 0, sizeof(saddr));

        saddr.sin_family = AF_INET;
        saddr.sin_addr = *(const struct in_addr *)addr;

        DWORD len = bufsize;

        if (WSAAddressToString((LPSOCKADDR)&saddr, sizeof(saddr), NULL, buf, &len)) {
            return NULL;
        }

        return buf;
    } else if (family == AF_INET6) {
        struct sockaddr_in6 saddr;
        memset(&saddr, 0, sizeof(saddr));

        saddr.sin6_family = AF_INET6;
        saddr.sin6_addr = *(const struct in6_addr *)addr;

        DWORD len = bufsize;

        if (WSAAddressToString((LPSOCKADDR)&saddr, sizeof(saddr), NULL, buf, &len)) {
            return NULL;
        }

        return buf;
    }

    return NULL;
}

static int inet_pton(sa_family_t family, const char *addrString, void *addrbuf)
{
    if (family == AF_INET) {
        struct sockaddr_in saddr;
        memset(&saddr, 0, sizeof(saddr));

        INT len = sizeof(saddr);

        if (WSAStringToAddress((LPTSTR)addrString, AF_INET, NULL, (LPSOCKADDR)&saddr, &len)) {
            return 0;
        }

        *(struct in_addr *)addrbuf = saddr.sin_addr;

        return 1;
    } else if (family == AF_INET6) {
        struct sockaddr_in6 saddr;
        memset(&saddr, 0, sizeof(saddr));

        INT len = sizeof(saddr);

        if (WSAStringToAddress((LPTSTR)addrString, AF_INET6, NULL, (LPSOCKADDR)&saddr, &len)) {
            return 0;
        }

        *(struct in6_addr *)addrbuf = saddr.sin6_addr;

        return 1;
    }

    return 0;
}

/* Check if socket is valid.
 *
 * return 1 if valid
 * return 0 if not valid
 */
int sock_valid(sock_t sock)
{
    if (sock == INVALID_SOCKET) {
        return 0;
    }

    return 1;
}

/* Close the socket.
 */
void kill_sock(sock_t sock)
{
    closesocket(sock);
}

/* Set socket as nonblocking
 *
 * return 1 on success
 * return 0 on failure
 */
int set_socket_nonblock(sock_t sock)
{
    u_long mode = 1;
    return (ioctlsocket(sock, FIONBIO, &mode) == 0);
}

/* Set socket to not emit SIGPIPE
 *
 * return 1 on success
 * return 0 on failure
 */
int set_socket_nosigpipe(sock_t sock)
{
    return 1;
}

/*  return current UNIX time in microseconds (us). */
static uint64_t current_time_actual(void)
{
    uint64_t time;
    /* This probably works fine */
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    time = ft.dwHighDateTime;
    time <<= 32;
    time |= ft.dwLowDateTime;
    time -= 116444736000000000ULL;
    return time / 10;
}


static uint64_t last_monotime;
static uint64_t add_monotime;

/* return current monotonic time in milliseconds (ms). */
uint64_t current_time_monotonic(void)
{
    uint64_t time;
    time = (uint64_t)GetTickCount() + add_monotime;

    if (time < last_monotime) { /* Prevent time from ever decreasing because of 32 bit wrap. */
        uint32_t add = ~0;
        add_monotime += add;
        time += add;
    }

    last_monotime = time;
    return time;
}

/* Function to receive data
 *  ip and port of sender is put into ip_port.
 *  Packet data is put into data.
 *  Packet length is put into length.
 */
static int receivepacket(Logger *log, sock_t sock, IP_Port *ip_port, uint8_t *data, uint32_t *length)
{
    memset(ip_port, 0, sizeof(IP_Port));
    struct sockaddr_storage addr;
    int addrlen = sizeof(addr);
    *length = 0;
    int fail_or_len = recvfrom(sock, (char *) data, MAX_UDP_PACKET_SIZE, 0, (struct sockaddr *)&addr, &addrlen);

    if (fail_or_len < 0) {

        if (fail_or_len < 0 && errno != EWOULDBLOCK) {
            LOGGER_ERROR(log, "Unexpected error reading from socket: %u, %s\n", errno, strerror(errno));
        }

        return -1; /* Nothing received. */
    }

    *length = (uint32_t)fail_or_len;

    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;

        ip_port->ip.family = addr_in->sin_family;
        ip_port->ip.ip4.in_addr = addr_in->sin_addr;
        ip_port->port = addr_in->sin_port;
    } else if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&addr;
        ip_port->ip.family = addr_in6->sin6_family;
        ip_port->ip.ip6.in6_addr = addr_in6->sin6_addr;
        ip_port->port = addr_in6->sin6_port;

        if (IPV6_IPV4_IN_V6(ip_port->ip.ip6)) {
            ip_port->ip.family = AF_INET;
            ip_port->ip.ip4.uint32 = ip_port->ip.ip6.uint32[3];
        }
    } else {
        return -1;
    }

    loglogdata(log, "=>O", data, MAX_UDP_PACKET_SIZE, *ip_port, *length);

    return 0;
}

void networking_poll(Networking_Core *net, void *userdata)
{
    if (net->family == 0) { /* Socket not initialized */
        return;
    }

    unix_time_update();

    IP_Port ip_port;
    uint8_t data[MAX_UDP_PACKET_SIZE];
    uint32_t length;

    while (receivepacket(net->log, net->sock, &ip_port, data, &length) != -1) {
        if (length < 1) {
            continue;
        }

        if (!(net->packethandlers[data[0]].function)) {
            LOGGER_WARNING(net->log, "[%02u] -- Packet has no handler", data[0]);
            continue;
        }

        net->packethandlers[data[0]].function(net->packethandlers[data[0]].object, ip_port, data, length, userdata);
    }
}

int plaform_networking_at_startup(void)
{
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
        return -1;
    }

    return 0;
}

/* TODO(irungentoo): Put this somewhere */
#if 0
static void at_shutdown(void)
{
    WSACleanup();
}
#endif

/* ipport_equal
 *  compares two IPAny_Port structures
 *  unset means unequal
 *
 * returns 0 when not equal or when uninitialized
 */
int ipport_equal(const IP_Port *a, const IP_Port *b)
{
    if (!a || !b) {
        return 0;
    }

    if (!a->port || (a->port != b->port)) {
        return 0;
    }

    return ip_equal(&a->ip, &b->ip);
}

/* nulls out ip */
void ip_reset(IP *ip)
{
    if (!ip) {
        return;
    }

    memset(ip, 0, sizeof(IP));
}

/* nulls out ip, sets family according to flag */
void ip_init(IP *ip, uint8_t ipv6enabled)
{
    if (!ip) {
        return;
    }

    memset(ip, 0, sizeof(IP));
    ip->family = ipv6enabled ? AF_INET6 : AF_INET;
}

/* checks if ip is valid */
int ip_isset(const IP *ip)
{
    if (!ip) {
        return 0;
    }

    return (ip->family != 0);
}

/* checks if ip is valid */
int ipport_isset(const IP_Port *ipport)
{
    if (!ipport) {
        return 0;
    }

    if (!ipport->port) {
        return 0;
    }

    return ip_isset(&ipport->ip);
}

/* copies an ip structure (careful about direction!) */
void ip_copy(IP *target, const IP *source)
{
    if (!source || !target) {
        return;
    }

    memcpy(target, source, sizeof(IP));
}

/* copies an ip_port structure (careful about direction!) */
void ipport_copy(IP_Port *target, const IP_Port *source)
{
    if (!source || !target) {
        return;
    }

    memcpy(target, source, sizeof(IP_Port));
}

/* ip_ntoa
 *   converts ip into a string
 *   uses a static buffer, so mustn't used multiple times in the same output
 *
 *   IPv6 addresses are enclosed into square brackets, i.e. "[IPv6]"
 *   writes error message into the buffer on error
 */
/* there would be INET6_ADDRSTRLEN, but it might be too short for the error message */
static char addresstext[96]; // TODO(irungentoo): magic number. Why not INET6_ADDRSTRLEN ?
const char *ip_ntoa(const IP *ip)
{
    if (ip) {
        if (ip->family == AF_INET) {
            /* returns standard quad-dotted notation */
            const struct in_addr *addr = (const struct in_addr *)&ip->ip4;

            addresstext[0] = 0;
            inet_ntop(ip->family, addr, addresstext, sizeof(addresstext));
        } else if (ip->family == AF_INET6) {
            /* returns hex-groups enclosed into square brackets */
            const struct in6_addr *addr = (const struct in6_addr *)&ip->ip6;

            addresstext[0] = '[';
            inet_ntop(ip->family, addr, &addresstext[1], sizeof(addresstext) - 3);
            size_t len = strlen(addresstext);
            addresstext[len] = ']';
            addresstext[len + 1] = 0;
        } else {
            snprintf(addresstext, sizeof(addresstext), "(IP invalid, family %u)", ip->family);
        }
    } else {
        snprintf(addresstext, sizeof(addresstext), "(IP invalid: NULL)");
    }

    /* brute force protection against lacking termination */
    addresstext[sizeof(addresstext) - 1] = 0;
    return addresstext;
}

/*
 * ip_parse_addr
 *  parses IP structure into an address string
 *
 * input
 *  ip: ip of AF_INET or AF_INET6 families
 *  length: length of the address buffer
 *          Must be at least INET_ADDRSTRLEN for AF_INET
 *          and INET6_ADDRSTRLEN for AF_INET6
 *
 * output
 *  address: dotted notation (IPv4: quad, IPv6: 16) or colon notation (IPv6)
 *
 * returns 1 on success, 0 on failure
 */
int ip_parse_addr(const IP *ip, char *address, size_t length)
{
    if (!address || !ip) {
        return 0;
    }

    if (ip->family == AF_INET) {
        const struct in_addr *addr = (const struct in_addr *)&ip->ip4;
        return inet_ntop(ip->family, addr, address, length) != NULL;
    }

    if (ip->family == AF_INET6) {
        const struct in6_addr *addr = (const struct in6_addr *)&ip->ip6;
        return inet_ntop(ip->family, addr, address, length) != NULL;
    }

    return 0;
}

/*
 * addr_parse_ip
 *  directly parses the input into an IP structure
 *  tries IPv4 first, then IPv6
 *
 * input
 *  address: dotted notation (IPv4: quad, IPv6: 16) or colon notation (IPv6)
 *
 * output
 *  IP: family and the value is set on success
 *
 * returns 1 on success, 0 on failure
 */
int addr_parse_ip(const char *address, IP *to)
{
    if (!address || !to) {
        return 0;
    }

    struct in_addr addr4;

    if (1 == inet_pton(AF_INET, address, &addr4)) {
        to->family = AF_INET;
        to->ip4.in_addr = addr4;
        return 1;
    }

    struct in6_addr addr6;

    if (1 == inet_pton(AF_INET6, address, &addr6)) {
        to->family = AF_INET6;
        to->ip6.in6_addr = addr6;
        return 1;
    }

    return 0;
}

/*
 * addr_resolve():
 *  uses getaddrinfo to resolve an address into an IP address
 *  uses the first IPv4/IPv6 addresses returned by getaddrinfo
 *
 * input
 *  address: a hostname (or something parseable to an IP address)
 *  to: to.family MUST be initialized, either set to a specific IP version
 *     (AF_INET/AF_INET6) or to the unspecified AF_UNSPEC (= 0), if both
 *     IP versions are acceptable
 *  extra can be NULL and is only set in special circumstances, see returns
 *
 * returns in *to a valid IPAny (v4/v6),
 *     prefers v6 if ip.family was AF_UNSPEC and both available
 * returns in *extra an IPv4 address, if family was AF_UNSPEC and *to is AF_INET6
 * returns 0 on failure, TOX_ADDR_RESOLVE_* on success.
 */
int addr_resolve(const char *address, IP *to, IP *extra)
{
    if (!address || !to) {
        return 0;
    }

    sa_family_t family = to->family;

    struct addrinfo *server = NULL;
    struct addrinfo *walker = NULL;
    struct addrinfo  hints;
    int rc;
    int result = 0;
    int done = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = family;
    hints.ai_socktype = SOCK_DGRAM; // type of socket Tox uses.

    if (networking_at_startup() != 0) {
        return 0;
    }

    rc = getaddrinfo(address, NULL, &hints, &server);

    // Lookup failed.
    if (rc != 0) {
        return 0;
    }

    IP ip4;
    ip_init(&ip4, 0); // ipv6enabled = 0
    IP ip6;
    ip_init(&ip6, 1); // ipv6enabled = 1

    for (walker = server; (walker != NULL) && !done; walker = walker->ai_next) {
        switch (walker->ai_family) {
            case AF_INET:
                if (walker->ai_family == family) { /* AF_INET requested, done */
                    struct sockaddr_in *addr = (struct sockaddr_in *)walker->ai_addr;
                    to->ip4.in_addr = addr->sin_addr;
                    result = TOX_ADDR_RESOLVE_INET;
                    done = 1;
                } else if (!(result & TOX_ADDR_RESOLVE_INET)) { /* AF_UNSPEC requested, store away */
                    struct sockaddr_in *addr = (struct sockaddr_in *)walker->ai_addr;
                    ip4.ip4.in_addr = addr->sin_addr;
                    result |= TOX_ADDR_RESOLVE_INET;
                }

                break; /* switch */

            case AF_INET6:
                if (walker->ai_family == family) { /* AF_INET6 requested, done */
                    if (walker->ai_addrlen == sizeof(struct sockaddr_in6)) {
                        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)walker->ai_addr;
                        to->ip6.in6_addr = addr->sin6_addr;
                        result = TOX_ADDR_RESOLVE_INET6;
                        done = 1;
                    }
                } else if (!(result & TOX_ADDR_RESOLVE_INET6)) { /* AF_UNSPEC requested, store away */
                    if (walker->ai_addrlen == sizeof(struct sockaddr_in6)) {
                        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)walker->ai_addr;
                        ip6.ip6.in6_addr = addr->sin6_addr;
                        result |= TOX_ADDR_RESOLVE_INET6;
                    }
                }

                break; /* switch */
        }
    }

    if (family == AF_UNSPEC) {
        if (result & TOX_ADDR_RESOLVE_INET6) {
            ip_copy(to, &ip6);

            if ((result & TOX_ADDR_RESOLVE_INET) && (extra != NULL)) {
                ip_copy(extra, &ip4);
            }
        } else if (result & TOX_ADDR_RESOLVE_INET) {
            ip_copy(to, &ip4);
        } else {
            result = 0;
        }
    }

    freeaddrinfo(server);
    return result;
}

/*
 * addr_resolve_or_parse_ip
 *  resolves string into an IP address
 *
 *  address: a hostname (or something parseable to an IP address)
 *  to: to.family MUST be initialized, either set to a specific IP version
 *     (AF_INET/AF_INET6) or to the unspecified AF_UNSPEC (= 0), if both
 *     IP versions are acceptable
 *  extra can be NULL and is only set in special circumstances, see returns
 *
 *  returns in *tro a matching address (IPv6 or IPv4)
 *  returns in *extra, if not NULL, an IPv4 address, if to->family was AF_UNSPEC
 *  returns 1 on success
 *  returns 0 on failure
 */
int addr_resolve_or_parse_ip(const char *address, IP *to, IP *extra)
{
    if (!addr_resolve(address, to, extra)) {
        if (!addr_parse_ip(address, to)) {
            return 0;
        }
    }

    return 1;
}
