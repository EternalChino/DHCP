//Angel Montalvo
//Student ID: 1002148576
// DHCP Library
// Jason Losh

#include <stdio.h>
#include <string.h>
#include "dhcp.h"
#include "arp.h"
#include "timer.h"

// DHCP constants

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPDECLINE  4
#define DHCPACK      5
#define DHCPNAK      6
#define DHCPRELEASE  7
#define DHCPINFORM   8

#define DHCP_DISABLED   0
#define DHCP_INIT       1
#define DHCP_SELECTING  2
#define DHCP_REQUESTING 3
#define DHCP_TESTING_IP 4
#define DHCP_BOUND      5
#define DHCP_RENEWING   6
#define DHCP_REBINDING  7
#define DHCP_INITREBOOT 8
#define DHCP_REBOOTING  9

#define DHCP_MAGIC_COOKIE 0x63825363

// DHCP options
#define DHCP_OPTION_SUBNET_MASK        1
#define DHCP_OPTION_ROUTER             3
#define DHCP_OPTION_DNS                6
#define DHCP_OPTION_REQUESTED_IP      50
#define DHCP_OPTION_LEASE_TIME        51
#define DHCP_OPTION_MESSAGE_TYPE      53
#define DHCP_OPTION_SERVER_IDENTIFIER 54
#define DHCP_OPTION_PARAMETER_LIST    55
#define DHCP_OPTION_END              255

// timing
#define DHCP_DISCOVER_RETRY_SECONDS 15
#define DHCP_REQUEST_RETRY_SECONDS   4
#define DHCP_ARP_TEST_SECONDS        2

// Globals

uint32_t xid = 0;
volatile uint32_t leaseSeconds = 0;
volatile uint32_t leaseT1 = 0;
volatile uint32_t leaseT2 = 0;

volatile bool discoverNeeded = false;
volatile bool requestNeeded  = false;
volatile bool releaseNeeded  = false;
volatile bool declineNeeded  = false;
volatile bool arpTestNeeded  = false;

bool ipConflictDetectionMode = false;

uint8_t dhcpOfferedIpAdd[4] = {0,0,0,0};
uint8_t dhcpServerIpAdd[4]  = {0,0,0,0};
uint8_t dhcpServerHwAdd[6] = {0,0,0,0,0,0};
volatile uint8_t dhcpState = DHCP_DISABLED;
volatile bool    dhcpEnabled = true;

// lease/config values being tested before commit
static uint8_t pendingIpAdd[4]     = {0,0,0,0};
static uint8_t pendingSnAdd[4]     = {0,0,0,0};
static uint8_t pendingGwAdd[4]     = {0,0,0,0};
static uint8_t pendingDnsAdd[4]    = {0,0,0,0};
static uint8_t pendingServerIp[4]  = {0,0,0,0};
static uint32_t pendingLease       = 0;

// software timing, driven by a 1 Hz timer callback
static volatile uint32_t discoverCountdown     = 0;
static volatile uint32_t requestRetryCountdown = 0;
static volatile uint32_t arpWindowCountdown    = 0;
static volatile uint32_t t1Countdown           = 0;
static volatile uint32_t t2Countdown           = 0;
static volatile uint32_t renewRetryCountdown   = 0;
static volatile uint32_t rebindRetryCountdown  = 0;

static bool dhcpTickTimerStarted = false;

// Local helpers

static bool localIpIsSet(void)
{
    uint8_t ip[4];
    getIpAddress(ip);
    return (ip[0] | ip[1] | ip[2] | ip[3]) != 0;
}

static void clearIpConfig(void)
{
    uint8_t zero[4] = {0,0,0,0};
    setIpAddress(zero);
    setIpSubnetMask(zero);
    setIpGatewayAddress(zero);
    setIpDnsAddress(zero);

    memset(dhcpServerHwAdd, 0, sizeof(dhcpServerHwAdd));
    memset(dhcpOfferedIpAdd, 0, sizeof(dhcpOfferedIpAdd));
    memset(dhcpServerIpAdd, 0, sizeof(dhcpServerIpAdd));
    memset(pendingIpAdd, 0, sizeof(pendingIpAdd));
    memset(pendingSnAdd, 0, sizeof(pendingSnAdd));
    memset(pendingGwAdd, 0, sizeof(pendingGwAdd));
    memset(pendingDnsAdd, 0, sizeof(pendingDnsAdd));
    memset(pendingServerIp, 0, sizeof(pendingServerIp));

    pendingLease = 0;
    leaseSeconds = 0;
    leaseT1 = 0;
    leaseT2 = 0;

    discoverNeeded = false;
    requestNeeded = false;
    releaseNeeded = false;
    declineNeeded = false;
    arpTestNeeded = false;
    ipConflictDetectionMode = false;

    discoverCountdown = 0;
    requestRetryCountdown = 0;
    arpWindowCountdown = 0;
    t1Countdown = 0;
    t2Countdown = 0;
    renewRetryCountdown = 0;
    rebindRetryCountdown = 0;
}

static uint16_t getUdpPayloadLength(etherHeader *ether)
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    udpHeader *udp = (udpHeader*)((uint8_t*)ip + ipHeaderLength);
    uint16_t udpLength = ntohs(udp->length);
    if (udpLength < sizeof(udpHeader))
        return 0;
    return udpLength - sizeof(udpHeader);
}

static void copy4(uint8_t dst[4], const uint8_t src[4])
{
    uint8_t i;
    for (i = 0; i < 4; i++)
        dst[i] = src[i];
}

static void setBroadcastIp(uint8_t ip[4])
{
    ip[0] = 255;
    ip[1] = 255;
    ip[2] = 255;
    ip[3] = 255;
}

static void applyPendingLease(void)
{
    setIpAddress(pendingIpAdd);
    setIpSubnetMask(pendingSnAdd);
    setIpGatewayAddress(pendingGwAdd);
    setIpDnsAddress(pendingDnsAdd);

    copy4(dhcpOfferedIpAdd, pendingIpAdd);
    copy4(dhcpServerIpAdd, pendingServerIp);

    if (pendingLease == 0)
        pendingLease = 3600;

    leaseSeconds = pendingLease; //20;
    leaseT1 = pendingLease / 2; //20;
    leaseT2 = (pendingLease * 7) / 8; //20:

    if (leaseT1 == 0) leaseT1 = 1;
    if (leaseT2 <= leaseT1) leaseT2 = leaseT1 + 1;
    if (leaseSeconds < leaseT2) leaseSeconds = leaseT2 + 1;

    t1Countdown = leaseT1;
    t2Countdown = leaseT2;
    renewRetryCountdown = 0;
    rebindRetryCountdown = 0;
    requestRetryCountdown = 0;
    arpWindowCountdown = 0;

    dhcpState = DHCP_BOUND;
}

static void callbackDhcpTickTimer(void);

// State functions

void setDhcpState(uint8_t state)
{
    dhcpState = state;
}

uint8_t getDhcpState()
{
    return dhcpState;
}

// New address functions

void callbackDhcpGetNewAddressTimer()
{
    if (dhcpEnabled && dhcpState == DHCP_SELECTING)
        discoverNeeded = true;
}

void requestDhcpNewAddress()
{
    clearIpConfig();

    xid = random32();
    if (xid == 0)
        xid = 1;

    dhcpState = DHCP_SELECTING;
    discoverNeeded = true;
    discoverCountdown = DHCP_DISCOVER_RETRY_SECONDS;
}

// Renew functions

void renewDhcp()
{
    if (!dhcpEnabled)
        return;

    requestDhcpNewAddress();
}



void callbackDhcpT1PeriodicTimer()
{
    if (dhcpEnabled && dhcpState == DHCP_RENEWING)
    {
        requestNeeded = true;
        renewRetryCountdown = DHCP_REQUEST_RETRY_SECONDS;
    }
}

void callbackDhcpT1HitTimer()
{
    if (dhcpEnabled && dhcpState == DHCP_BOUND)
    {
        dhcpState = DHCP_RENEWING;
        requestNeeded = true;
        renewRetryCountdown = DHCP_REQUEST_RETRY_SECONDS;
    }
}

// Rebind functions

void rebindDhcp()
{
    if (!dhcpEnabled)
        return;

    if (dhcpState == DHCP_BOUND || dhcpState == DHCP_RENEWING || dhcpState == DHCP_REBINDING)
    {
        dhcpState = DHCP_REBINDING;
        requestNeeded = true;
        rebindRetryCountdown = DHCP_REQUEST_RETRY_SECONDS;
    }
}

void callbackDhcpT2PeriodicTimer()
{
    if (dhcpEnabled && dhcpState == DHCP_REBINDING)
    {
        requestNeeded = true;
        rebindRetryCountdown = DHCP_REQUEST_RETRY_SECONDS;
    }
}

void callbackDhcpT2HitTimer()
{
    if (dhcpEnabled && (dhcpState == DHCP_BOUND || dhcpState == DHCP_RENEWING))
    {
        dhcpState = DHCP_REBINDING;
        requestNeeded = true;
        rebindRetryCountdown = 0;//DHCP_REQUEST_RETRY_SECONDS;
    }
}

// End of lease timer

void callbackDhcpLeaseEndTimer()
{
    if (!dhcpEnabled)
        return;

    clearIpConfig();
    dhcpState = DHCP_INIT;
    requestDhcpNewAddress();
}

// Release functions

void releaseDhcp()
{
    if (!dhcpEnabled)
        return;

    if (dhcpState == DHCP_BOUND || dhcpState == DHCP_RENEWING || dhcpState == DHCP_REBINDING)
        releaseNeeded = true;
}

// IP conflict detection

void callbackDhcpIpConflictWindow()
{
    arpWindowCountdown = 0;

    if (ipConflictDetectionMode)
    {
        declineNeeded = true;
        dhcpState = DHCP_INIT;
        discoverCountdown = DHCP_DISCOVER_RETRY_SECONDS;
    }
    else
    {
        applyPendingLease();
    }
}

void requestDhcpIpConflictTest()
{
    ipConflictDetectionMode = false;
    arpTestNeeded = true;
    arpWindowCountdown = DHCP_ARP_TEST_SECONDS;
}

bool isDhcpIpConflictDetectionMode()
{
    return ipConflictDetectionMode;
}

// Lease functions

uint32_t getDhcpLeaseSeconds()
{
    return leaseSeconds;
}

// Timer tick

static void callbackDhcpTickTimer(void)
{
    if (!dhcpEnabled)
        return;

    if (leaseSeconds > 0 && (dhcpState == DHCP_BOUND || dhcpState == DHCP_RENEWING || dhcpState == DHCP_REBINDING))
    {
        leaseSeconds--;
        if (leaseSeconds == 0)
            callbackDhcpLeaseEndTimer();
    }

    if (discoverCountdown > 0 && dhcpState == DHCP_SELECTING)
    {
        discoverCountdown--;
        if (discoverCountdown == 0)
        {
            callbackDhcpGetNewAddressTimer();
            discoverCountdown = DHCP_DISCOVER_RETRY_SECONDS;
        }
    }

    if (requestRetryCountdown > 0 && dhcpState == DHCP_REQUESTING)
    {
        requestRetryCountdown--;
        if (requestRetryCountdown == 0)
        {
            requestNeeded = true;
            requestRetryCountdown = DHCP_REQUEST_RETRY_SECONDS;
        }
    }

    if (arpWindowCountdown > 0 && dhcpState == DHCP_TESTING_IP)
    {
        arpWindowCountdown--;
        if (arpWindowCountdown == 0)
            callbackDhcpIpConflictWindow();
    }

    if (t1Countdown > 0 && dhcpState == DHCP_BOUND)
    {
        t1Countdown--;
        if (t1Countdown == 0)
            callbackDhcpT1HitTimer();
    }

    if (t2Countdown > 0 && (dhcpState == DHCP_BOUND || dhcpState == DHCP_RENEWING))
    {
        t2Countdown--;
        if (t2Countdown == 0)
            callbackDhcpT2HitTimer();
    }

    if (renewRetryCountdown > 0 && dhcpState == DHCP_RENEWING)
    {
        renewRetryCountdown--;
        if (renewRetryCountdown == 0)
            callbackDhcpT1PeriodicTimer();
    }

    if (rebindRetryCountdown > 0 && dhcpState == DHCP_REBINDING)
    {
        rebindRetryCountdown--;
        if (rebindRetryCountdown == 0)
            callbackDhcpT2PeriodicTimer();
    }
}

// Determines whether packet is DHCP
// Must be a UDP packet

bool isDhcpResponse(etherHeader* ether)
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    udpHeader *udp = (udpHeader*)((uint8_t*)ip + ipHeaderLength);
    dhcpFrame *dhcp = (dhcpFrame*)udp->data;

    if (!isUdp(ether))
        return false;

    if (ntohs(udp->sourcePort) != DHCP_SERVER_PORT)
        return false;

    if (ntohs(udp->destPort) != DHCP_CLIENT_PORT)
        return false;

    if (dhcp->op != 2)
        return false;

    if (ntohl(dhcp->magicCookie) != DHCP_MAGIC_COOKIE)
        return false;

    if (ntohl(dhcp->xid) != xid)
        return false;

    return true;
}

// Send DHCP message

void sendDhcpMessage(etherHeader *ether, uint8_t type)
{
    uint8_t i;
    uint8_t localHwAddress[6];
    uint8_t localIpAddress[4] = {0,0,0,0};
    uint8_t destIp[4];
    uint8_t *opt;
    uint16_t optionsLength;
    uint16_t udpLength;
    uint16_t ipHeaderLength;
    uint16_t totalSize;
    uint32_t sum;
    uint16_t tmp16;

    ipHeader *ip;
    udpHeader *udp;
    dhcpFrame *dhcp;

    getEtherMacAddress(localHwAddress);
    getIpAddress(localIpAddress);
    setBroadcastIp(destIp);

    // Ethernet header
    bool useServerMac = (type == DHCPREQUEST && dhcpState == DHCP_RENEWING) && (dhcpServerHwAdd[0] | dhcpServerHwAdd[1] | dhcpServerHwAdd[2] | dhcpServerHwAdd[3] | dhcpServerHwAdd[4] | dhcpServerHwAdd[5]);

    for (i = 0; i < HW_ADD_LENGTH; i++)
    {
        ether->sourceAddress[i] = localHwAddress[i];
        ether->destAddress[i] = useServerMac ? dhcpServerHwAdd[i] : 0xFF;
    }

    ether->frameType = htons(TYPE_IP);

    // IP header
    ip = (ipHeader*)ether->data;
    ip->rev = 4;
    ip->size = 5;
    ip->typeOfService = 0;
    ip->id = getEtherId();
    incEtherId();
    ip->flagsAndOffset = 0;
    ip->ttl = 128;
    ip->protocol = PROTOCOL_UDP;
    ip->headerChecksum = 0;

    // source / dest IP
    if ((type == DHCPREQUEST || type == DHCPRELEASE) && (dhcpState == DHCP_RENEWING || dhcpState == DHCP_REBINDING || dhcpState == DHCP_BOUND) && localIpIsSet())
    {
        copy4(ip->sourceIp, localIpAddress);
    }
    else
    {
        memset(ip->sourceIp, 0, 4);
    }

    if (type == DHCPRELEASE && (dhcpServerIpAdd[0] | dhcpServerIpAdd[1] | dhcpServerIpAdd[2] | dhcpServerIpAdd[3]))
    {
        copy4(destIp, dhcpServerIpAdd);
    }
    else if (type == DHCPREQUEST && dhcpState == DHCP_RENEWING && (dhcpServerIpAdd[0] | dhcpServerIpAdd[1] | dhcpServerIpAdd[2] | dhcpServerIpAdd[3]))
    {
        copy4(destIp, dhcpServerIpAdd);
    }
    else
    {
        setBroadcastIp(destIp);
    }


    copy4(ip->destIp, destIp);
    ipHeaderLength = ip->size * 4;

    // UDP header
    udp = (udpHeader*)((uint8_t*)ip + ipHeaderLength);
    udp->sourcePort = htons(DHCP_CLIENT_PORT);
    udp->destPort   = htons(DHCP_SERVER_PORT);

    // DHCP payload
    dhcp = (dhcpFrame*)udp->data;
    memset(dhcp, 0, sizeof(dhcpFrame) + 64);

    dhcp->op = 1;
    dhcp->htype = 1;
    dhcp->hlen = HW_ADD_LENGTH;
    dhcp->hops = 0;
    dhcp->xid = htonl(xid);
    dhcp->secs = 0;

    if (type == DHCPDISCOVER)
        dhcp->flags = htons(0x8000);
    else if (type == DHCPREQUEST && (dhcpState == DHCP_REQUESTING || dhcpState == DHCP_REBINDING))
        dhcp->flags = htons(0x8000);
    else
        dhcp->flags = 0;

    if ((type == DHCPREQUEST || type == DHCPRELEASE) && (dhcpState == DHCP_RENEWING || dhcpState == DHCP_REBINDING || dhcpState == DHCP_BOUND) && localIpIsSet())
    {
        copy4(dhcp->ciaddr, localIpAddress);
    }

    for (i = 0; i < HW_ADD_LENGTH; i++)
    dhcp->chaddr[i] = localHwAddress[i];
    dhcp->magicCookie = htonl(DHCP_MAGIC_COOKIE);
    opt = dhcp->options;

    // option 53: message type
    *opt++ = DHCP_OPTION_MESSAGE_TYPE;
    *opt++ = 1;
    *opt++ = type;

    if (type == DHCPDISCOVER)
    {
        // parameter request list
        *opt++ = DHCP_OPTION_PARAMETER_LIST;
        *opt++ = 5;
        *opt++ = DHCP_OPTION_SUBNET_MASK;
        *opt++ = DHCP_OPTION_ROUTER;
        *opt++ = DHCP_OPTION_DNS;
        *opt++ = DHCP_OPTION_LEASE_TIME;
        *opt++ = DHCP_OPTION_SERVER_IDENTIFIER;
    }
    else if (type == DHCPREQUEST)
    {
        uint8_t reqIp[4] = {0,0,0,0};
        bool includeReqIp = false;
        bool includeServerId = false;

        if (dhcpState == DHCP_REQUESTING)
        {
            copy4(reqIp, dhcpOfferedIpAdd);
            includeReqIp = true;
            includeServerId = true;
        }
        else if (dhcpState == DHCP_RENEWING)
        {
            includeReqIp = false;
            includeServerId = false;
        }
        else if (dhcpState == DHCP_REBINDING)
        {
            includeReqIp = false;
            includeServerId = false;
        }

        if (includeReqIp)
        {
            *opt++ = DHCP_OPTION_REQUESTED_IP;
            *opt++ = 4;
            for (i = 0; i < 4; i++)
                *opt++ = reqIp[i];
        }

        if (includeServerId)
        {
            *opt++ = DHCP_OPTION_SERVER_IDENTIFIER;
            *opt++ = 4;
            for (i = 0; i < 4; i++)
                *opt++ = dhcpServerIpAdd[i];
        }

        *opt++ = DHCP_OPTION_PARAMETER_LIST;
        *opt++ = 5;
        *opt++ = DHCP_OPTION_SUBNET_MASK;
        *opt++ = DHCP_OPTION_ROUTER;
        *opt++ = DHCP_OPTION_DNS;
        *opt++ = DHCP_OPTION_LEASE_TIME;
        *opt++ = DHCP_OPTION_SERVER_IDENTIFIER;
    }
    else if (type == DHCPDECLINE)
    {
        *opt++ = DHCP_OPTION_REQUESTED_IP;
        *opt++ = 4;
        for (i = 0; i < 4; i++)
            *opt++ = pendingIpAdd[i];

        *opt++ = DHCP_OPTION_SERVER_IDENTIFIER;
        *opt++ = 4;
        for (i = 0; i < 4; i++)
            *opt++ = pendingServerIp[i];
    }
    else if (type == DHCPRELEASE)
    {
        *opt++ = DHCP_OPTION_SERVER_IDENTIFIER;
        *opt++ = 4;
        for (i = 0; i < 4; i++)
            *opt++ = dhcpServerIpAdd[i];
    }

    *opt++ = DHCP_OPTION_END;
    optionsLength = (uint16_t)(opt - dhcp->options);
    udpLength = sizeof(udpHeader) + sizeof(dhcpFrame) + optionsLength;
    ip->length = htons(ipHeaderLength + udpLength);
    udp->length = htons(udpLength);
    calcIpChecksum(ip);

    // UDP checksum
    udp->check = 0;
    sum = 0;
    sumIpWords(ip->sourceIp, 8, &sum);
    tmp16 = ip->protocol;
    sum += (tmp16 & 0xFF) << 8;
    sumIpWords(&udp->length, 2, &sum);
    sumIpWords(udp, udpLength, &sum);
    udp->check = getIpChecksum(sum);

    totalSize = sizeof(etherHeader) + ipHeaderLength + udpLength;
    if (putEtherPacket(ether, totalSize))
        putsUart0("tx ok\r\n");
    else
        putsUart0("tx fail\r\n");
}

// Option parser

uint8_t* getDhcpOption(etherHeader *ether, uint8_t option, uint8_t* length)
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    udpHeader *udp = (udpHeader*)((uint8_t*)ip + ipHeaderLength);
    dhcpFrame *dhcp = (dhcpFrame*)udp->data;
    uint16_t payloadLen = getUdpPayloadLength(ether);
    uint16_t dhcpFixedLen = sizeof(dhcpFrame);
    uint8_t *p;
    uint8_t *end;

    if (length != 0)
        *length = 0;

    if (payloadLen < dhcpFixedLen)
        return 0;

    p = dhcp->options;
    end = ((uint8_t*)dhcp) + payloadLen;

    while (p < end)
    {
        uint8_t code = *p++;

        if (code == 0)
            continue;

        if (code == DHCP_OPTION_END)
            break;

        if (p >= end)
            break;

        uint8_t len = *p++;
        if ((uint16_t)(end - p) < len)
            break;

        if (code == option)
        {
            if (length != 0)
                *length = len;
            return p;
        }

        p += len;
    }

    return 0;
}

// Determines whether packet is DHCP offer response to DHCP discover

bool isDhcpOffer(etherHeader *ether, uint8_t ipOfferedAdd[])
{
    uint8_t len;
    uint8_t *msgType;
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    udpHeader *udp = (udpHeader*)((uint8_t*)ip + ipHeaderLength);
    dhcpFrame *dhcp = (dhcpFrame*)udp->data;

    if (!isDhcpResponse(ether))
        return false;
    msgType = getDhcpOption(ether, DHCP_OPTION_MESSAGE_TYPE, &len);
    if (msgType == 0 || len != 1 || msgType[0] != DHCPOFFER)
        return false;

    copy4(ipOfferedAdd, dhcp->yiaddr);
    return true;
}

// Determines whether packet is DHCP ACK response to DHCP request

bool isDhcpAck(etherHeader *ether)
{
    uint8_t len;
    uint8_t *msgType;

    if (!isDhcpResponse(ether))
        return false;

    msgType = getDhcpOption(ether, DHCP_OPTION_MESSAGE_TYPE, &len);
    if (msgType == 0 || len != 1)
        return false;

    return msgType[0] == DHCPACK;
}

// Handle a DHCP ACK

void handleDhcpAck(etherHeader *ether)
{
    uint8_t len;
    uint8_t *opt;
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    udpHeader *udp = (udpHeader*)((uint8_t*)ip + ipHeaderLength);
    dhcpFrame *dhcp = (dhcpFrame*)udp->data;

    if (dhcpState == DHCP_RENEWING || dhcpState == DHCP_REBINDING)
    {
        uint8_t currentIp[4];
        getIpAddress(currentIp);
        copy4(pendingIpAdd, currentIp);
    }
    else
    {
        copy4(pendingIpAdd, dhcp->yiaddr);
    }

    memset(pendingSnAdd, 0, sizeof(pendingSnAdd));
    memset(pendingGwAdd, 0, sizeof(pendingGwAdd));
    memset(pendingDnsAdd, 0, sizeof(pendingDnsAdd));
    memset(pendingServerIp, 0, sizeof(pendingServerIp));
    pendingLease = 3600;

    opt = getDhcpOption(ether, DHCP_OPTION_SUBNET_MASK, &len);
    if (opt != 0 && len >= 4)
        copy4(pendingSnAdd, opt);

    opt = getDhcpOption(ether, DHCP_OPTION_ROUTER, &len);
    if (opt != 0 && len >= 4)
        copy4(pendingGwAdd, opt);

    opt = getDhcpOption(ether, DHCP_OPTION_DNS, &len);
    if (opt != 0 && len >= 4)
        copy4(pendingDnsAdd, opt);

    opt = getDhcpOption(ether, DHCP_OPTION_SERVER_IDENTIFIER, &len);
    if (opt != 0 && len >= 4)
        copy4(pendingServerIp, opt);
    else
        copy4(pendingServerIp, ip->sourceIp);

    opt = getDhcpOption(ether, DHCP_OPTION_LEASE_TIME, &len);
    if (opt != 0 && len == 4)
        pendingLease = ntohl(*(uint32_t*)opt);

    if (dhcpState == DHCP_REQUESTING)
    {
        dhcpState = DHCP_TESTING_IP;
        requestDhcpIpConflictTest();
    }
    else
    {
        applyPendingLease();
    }
}

// Message requests

bool isDhcpDiscoverNeeded()
{
    return discoverNeeded;
}

bool isDhcpRequestNeeded()
{
    return requestNeeded;
}

bool isDhcpReleaseNeeded()
{
    return releaseNeeded;
}

void sendDhcpPendingMessages(etherHeader *ether)
{
    uint8_t zeroIp[4] = {0,0,0,0};

    if (!dhcpEnabled)
        return;

    if (discoverNeeded)
    {
        discoverNeeded = false;
        sendDhcpMessage(ether, DHCPDISCOVER);
    }

    if (requestNeeded)
    {
        requestNeeded = false;
        sendDhcpMessage(ether, DHCPREQUEST);
    }

    if (arpTestNeeded)
    {
        arpTestNeeded = false;
        sendArpRequest(ether, zeroIp, pendingIpAdd);
    }

    if (declineNeeded)
    {
        declineNeeded = false;
        sendDhcpMessage(ether, DHCPDECLINE);
        requestDhcpNewAddress();
    }

    if (releaseNeeded)
    {
        releaseNeeded = false;
        sendDhcpMessage(ether, DHCPRELEASE);
        clearIpConfig();
        dhcpState = DHCP_INIT;
    }
}

void processDhcpResponse(etherHeader *ether)
{
    uint8_t len;
    uint8_t *msgType;
    uint8_t offeredIp[4];

    if (!isDhcpResponse(ether))
        return;

    msgType = getDhcpOption(ether, DHCP_OPTION_MESSAGE_TYPE, &len);
    if (msgType == 0 || len != 1)
        return;

    if (msgType[0] == DHCPOFFER && dhcpState == DHCP_SELECTING)
    {
        if (isDhcpOffer(ether, offeredIp))
        {
            uint8_t *serverId;
            copy4(dhcpOfferedIpAdd, offeredIp);
            uint8_t i = 0;
            for (i = 0; i < HW_ADD_LENGTH; i++)
                dhcpServerHwAdd[i] = ether->sourceAddress[i];

            serverId = getDhcpOption(ether, DHCP_OPTION_SERVER_IDENTIFIER, &len);
            if (serverId != 0 && len >= 4)
                copy4(dhcpServerIpAdd, serverId);

            dhcpState = DHCP_REQUESTING;
            requestNeeded = true;
            requestRetryCountdown = DHCP_REQUEST_RETRY_SECONDS;
        }
    }

    else if (msgType[0] == DHCPACK && (dhcpState == DHCP_REQUESTING || dhcpState == DHCP_RENEWING || dhcpState == DHCP_REBINDING))
    {
        uint8_t i = 0;
        for (i = 0; i < HW_ADD_LENGTH; i++)
            dhcpServerHwAdd[i] = ether->sourceAddress[i];

        handleDhcpAck(ether);
    }

    else if (msgType[0] == DHCPNAK && (dhcpState == DHCP_REQUESTING || dhcpState == DHCP_RENEWING || dhcpState == DHCP_REBINDING))
    {
        requestDhcpNewAddress();
    }
}

void processDhcpArpResponse(etherHeader *ether)
{
    arpPacket *arp = (arpPacket*)ether->data;
    uint8_t i;
    bool match = true;

    if (dhcpState != DHCP_TESTING_IP)
        return;

    for (i = 0; i < 4; i++)
    {
        if (arp->sourceIp[i] != pendingIpAdd[i])
            match = false;
    }

    if (match)
        ipConflictDetectionMode = true;
}

// DHCP control functions

void enableDhcp()
{
    dhcpEnabled = true;

    if (!dhcpTickTimerStarted)
    {
        startPeriodicTimer(callbackDhcpTickTimer, 1);
        dhcpTickTimerStarted = true;
    }

    requestDhcpNewAddress();
}

void disableDhcp()
{
    dhcpEnabled = false;
    dhcpState = DHCP_DISABLED;
    clearIpConfig();
}

bool isDhcpEnabled()
{
    return dhcpEnabled;
}

