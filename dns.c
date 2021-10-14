#include "dns.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
 typedef struct dnsCell_ {
     int IP;
     char* HostName;
     struct dnsCell_* nextCell;
 } dnsCell;

const int DNSsize = 12839;

DNSHandle InitDNS()
{
   dnsCell* HashTable = (dnsCell*)malloc(DNSsize*sizeof(dnsCell));
   memset(HashTable, 0, DNSsize * sizeof(dnsCell));
   return (DNSHandle)HashTable;
}

void LoadHostsFile(DNSHandle hDNS, const char* hostsFilePath)
{
    dnsCell* HashTable = (dnsCell*)hDNS;
    FILE* HostsFile;
    fopen_s(&HostsFile,hostsFilePath,"r");
    char* HostName = (char*)malloc(220);
    int ip1, ip2, ip3, ip4;
    int IP, Hash;
    size_t HostNameSize = 0 ;
        while(5 == fscanf_s(HostsFile,"%d.%d.%d.%d %s",&ip1,&ip2,&ip3,&ip4,HostName,220))
        {
        IP = (ip1 & 0xFF) << 24 |
            (ip2 & 0xFF) << 16 |
            (ip3 & 0xFF) << 8 |
            (ip4 & 0xFF);
        HostNameSize = strlen(HostName);
        Hash = HashFunc(HostName);
        dnsCell* cell;
        if (HashTable[Hash].HostName == NULL)
        {
            HashTable[Hash].HostName = (char*)malloc(HostNameSize + 1);
            strcpy_s(HashTable[Hash].HostName,HostNameSize+1,HostName);
            HashTable[Hash].IP = IP;
        }
        else
        {
            cell = (dnsCell*)malloc(sizeof(dnsCell));
            cell->HostName = (char*)malloc(HostNameSize + 1);
            strcpy_s(cell->HostName,HostNameSize+1,HostName);
            cell->IP =IP;
            cell->nextCell = HashTable[Hash].nextCell;
            HashTable[Hash].nextCell = cell;
        }
    }
    free(HostName);
    fclose(HostsFile);
}
int HashFunc(const char* hostName) {
    int HashID = hostName[0];
    size_t size = strlen(hostName);
    for (int i = 1; i < size; i++) {
        HashID += hostName[0] + 5*hostName[i];
    }
  
    return HashID%DNSsize;
}
IPADDRESS DnsLookUp(DNSHandle hDNS, const char* hostName)
{
    unsigned int Hash = HashFunc(hostName);
    dnsCell* target = &((dnsCell*)hDNS)[Hash];
    while (target != NULL && target->HostName != NULL && strcmp(target->HostName, hostName) != 0)
    {
        target = target->nextCell;
    }
    if (target != NULL && target->HostName != NULL)
        return target->IP;
    return INVALID_IP_ADDRESS;
}

void ShutdownDNS(DNSHandle hDNS)
{
    dnsCell* HashTable = (dnsCell*)hDNS;
    if (HashTable == NULL) return;
    dnsCell* cell;
    dnsCell* tempCell;
    for (int i = 0; i < DNSsize; i++) {
        cell =  HashTable[i].nextCell;
        while (cell != NULL)
        {
            tempCell = cell;
            cell = cell->nextCell;
            free(tempCell);
        }
    }
        free(HashTable);
}