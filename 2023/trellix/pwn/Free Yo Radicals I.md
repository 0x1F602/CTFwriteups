# Free Yo Radicals I

#### Information gathering

Each time the drone sends a message, it has a 46 byte long message that changes slightly, with some padding at the end it seems to make it fixed width. It sends three messages and closes the TCP connection. The server binary sends back a mSv measurement and location identifier of some kind.

We can use python to analyze the hex data.

I've extracted the client's payloads here:

```
ac16ec2c0e270f0e636580b00e00010e444e31330e766f00000e000000000e000000000e00000000000001400e0c
ac16ec2c0e270f0e636580b00e00010e484d31330e566f00000e000000000e000000000e00000000000000390e0c
ac16ec2c0e270f0e636580b00e00050e000000000e000000000e000000000e000000000e00000000000000000e0c

ac16ec2c0e270f0e636581d40e00010e444d30360e637300000e000000000e000000000e00000000000000780e0c
ac16ec2c0e270f0e636581d40e00030e000000000e000000000e000000000e000000000e00000000000000000e0c
ac16ec2c0e270f0e636581d40e00050e000000000e000000000e000000000e000000000e00000000000000000e0c
```

I wrote a little python3 script to "spaghettify" this code so that I can use the simple `diff` tool to analyze these.

```
import sys
n = 2
string = sys.argv[1]
# https://www.geeksforgeeks.org/python-split-string-in-groups-of-n-consecutive-characters/
out = [(string[i:i+n]) for i in range(0, len(string), n)]
for chunk in out:
        print(chunk)
```

I determined that chunks of two were the minimum, meaning each client-side payload would have 23 chunks (46 divided by 2).

I noticed that the final client-side payload is very similar. The server's response after this payload is `[+] Bye bye!` so this somehow closes the connection. The byte that changes should be watched carefully though.

The first message in both captures are only different in 9 pairs.

The second messages are only different in 10 pairs.

The third message only differs by 2 pairs.

We can and will use this information to use the byte arrays to pack a new structure, which we will send to the server binary in sequence.

Taking the first section of bytes and turning them into decimal reveals a pattern.

```
└─$ python3 message.py
first_skeleton
[128, 176]
[78, 49, 51]
[118, 111]
[1]
second_skeleton
[129, 212]
[77, 48, 54]
[99, 115]
[0]
```

There are small increments in some of these numbers, suggesting a counter.



```
$ file server_binary 
server_binary: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a6197674e296f86bbda65ded9cee1df878f5a064, with debug_info, not stripped
```

```
$ strings server_binary
...
mSv: %lu                                             
Location: %s                          
./flag
Error: Found bad deliminator, Invalid packet
Error: Incorrect termination, Invalid packet
Valid packet
Connected
Waiting for data... 
[+] Bye bye!
action: %d
Created new coordinate
Error: Termination char found in coordinate
Created new radiation value!
Send error message. Termination char found in radiation value
Error: Max Entries reached
Deleted requested coordinate
Warning: There are no coordinates left to delete
Deleted requested radiation value
Warning: There are no radiation values left to delete
Warning: There is no entries to print
[+] Listening port: %d
Socket
socket--bind
socket--listen
%s:%d connected
Failed to fork
...
```

The program appears to have been compiled with symbols.

That means we can get a lot more information out of it.

I used `gdb server_binary`, then `run` until it got to the waiting prompt. Then I hit `ctrl-z` to pause the program. In gdb I did `set logging on` and then `info functions`. This created a file gdb.txt with the name of every function (huge list). I have limited that to only main.c.

```
$ ack -A20 "File main.c" gdb.txt
File main.c:
156:    int checkForTermination(char *, int);
376:    int main(int, char **);
137:    void parse_packet(struct packet *, unsigned char *);
89:     void print_flag(int);
77:     char *send_num(unsigned long, char *);
83:     char *send_str(char *, char *);
97:     int validate(unsigned char *);
166:    void zechallenge(int);
. . .
```
I noticed this `packet` structure which appears to be custom.
I used `ptype /o packet` in `gdb`.

```
(gdb) ptype /o packet
type = struct packet {
/*      0      |       4 */    int clientfd;
/*      4      |       4 */    int payload_ip;
/*      8      |       4 */    int payload_port;
/*     12      |       4 */    int timestamp;
/*     16      |       4 */    int action;
/*     20      |      16 */    char datafield_1[16];
/*     36      |       8 */    char datafield_2[8];

                               /* total size (bytes):   44 */
                             }
```
Now we have revealed the structure of the packet, sort of.

After even more reverse engineering, I broke down the first message like so:

```
# ac16ec2c 0e
# 270f 0e
# 636580b0 0e
# 0001 0e
# 444e3133 0e
# 766f0000 0e
# 00000000 0e
# 00000000 0e
# 00 00 00 00 00 00 01 40 0e
# 0c
```

The `0x0e` is a delimiter. The `0x0c` is the terminator at the end.

The first field is the client's IP address in decimal format.

The second field is the port number, as an unsigned integer.

The third field is a timestamp in unix epoch form. In this case, `Friday, November 4, 2022 9:14:24 PM GMT`.

The fourth field is a code for an action to do.

The next 4 fields are 4 chunks that make up datafield_1.

The next 8 bytes (not counting the delimiter) is datafield_2.

#### Escalation

I used Ghidra to decompile the binary.

```void zechallenge(int clientfd)
void zechallenge(int clientfd)
{
  bool bVar1;
  bool bVar2;
  bool bVar3;
  int iVar4;
  size_t sVar5;
  ssize_t sVar6;
  __uint64_t _Var7;
  long lVar8;
  packet *ppVar9;
  long in_FS_OFFSET;
  byte bVar10;
  int numentries;
  int count;
  int loopout;
  uint choice;
  uint index;
  ulong del_value;
  string *curstr;
  number *curnum;
  string *current;
  string *previous;
  number *current_1;
  number *previous_1;
  string *tempstr;
  number *tempnum;
  char *hellomessage;
  char *optionsmessage;
  char *byemessage;
  timeval tv;
  _Bool ops_completed [4];
  packet p;
  char buffer [46];
  char message [46];
  long local_10;
  
  bVar10 = 0;
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  curstr = (string *)0x0;
  curnum = (number *)0x0;
  bVar1 = false;
  bVar2 = false;
  bVar3 = false;
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  numentries = 0;
  setsockopt(clientfd,1,0x14,&tv,0x10);
  setsockopt(clientfd,1,0x15,&tv,0x10);
  sVar5 = strlen("Connected\n");
  send(clientfd,"Connected\n",sVar5,0);
  do {
    while( true ) {
      sVar5 = strlen("\nWaiting for data... \n");
      sVar6 = send(clientfd,"\nWaiting for data... \n",sVar5,0);
      if ((sVar6 < 0) || (sVar6 = recv(clientfd,buffer,0x2e,0), sVar6 == 0)) {
        close(clientfd);
        if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
          __stack_chk_fail();
        }
        return;
      }
      ppVar9 = &p;
      for (lVar8 = 5; lVar8 != 0; lVar8 = lVar8 + -1) {
        *(undefined8 *)ppVar9 = 0;
        ppVar9 = (packet *)((long)ppVar9 + (ulong)bVar10 * -0x10 + 8);
      }
      ppVar9->clientfd = 0;
      parse_packet(&p,(uchar *)buffer);
      printf("action: %d\n",(ulong)(uint)p.action);
      if (p.action == 2) break;
      if (p.action < 3) {
        if (p.action == 1) {
          if (!bVar1) {
            bVar1 = true;
          }
          if (numentries < 6) {
            iVar4 = checkForTermination(p.datafield_1,0x10);
            if (iVar4 == 0) {
              curstr = (string *)malloc(0x28);
              *(undefined8 *)curstr->buffer = p.datafield_1._0_8_;
              *(undefined8 *)(curstr->buffer + 8) = p.datafield_1._8_8_;
              curstr->buffer[0x10] = '\0';
              curstr->print = send_str;
              curstr->next = string_head;
              string_head = curstr;
              puts("Created new coordinate");
            }
            else {
              puts("Error: Termination char found in coordinate");
            }
            iVar4 = checkForTermination(p.datafield_2,8);
            if (iVar4 == 0) {
              curnum = (number *)malloc(0x28);
              curnum->num = (ulong)p.datafield_2;
              _Var7 = __bswap_64(curnum->num);
              curnum->num = _Var7;
              curnum->print = send_num;
              curnum->next = number_head;
              number_head = curnum;
              puts("Created new radiation value!");
            }
            else {
              puts("Send error message. Termination char found in radiation value\n");
            }
            numentries = numentries + 1;
          }
          else {
            puts("Error: Max Entries reached");
          }
        }
      }
      else if (p.action == 3) {
        if (!bVar3) {
          bVar3 = true;
        }
        if (numentries == 0) {
          puts("Warning: There is no entries to print");
        }
        else {
          count = 0;
          _Var7 = __bswap_64((__uint64_t)p.datafield_2);
          if (_Var7 == 1) {
            tempstr = curstr;
            tempnum = curnum;
            count = 5;
          }
          else {
            tempstr = string_head;
            tempnum = number_head;
          }
          for (; ((tempnum != (number *)0x0 && (tempstr != (string *)0x0)) && (count < 6));
              count = count + 1) {
            (*tempnum->print)(tempnum->num,message);
            sVar5 = strlen(message);
            send(clientfd,message,sVar5,0);
            (*tempstr->print)(tempstr->buffer,message);
            sVar5 = strlen(message);
            send(clientfd,message,sVar5,0);
            tempnum = tempnum->next;
            tempstr = tempstr->next;
          }
        }
      }
      else if (p.action == 5) {
        if (((bVar1) && (bVar2)) && (bVar3)) {
          print_flag(clientfd);
        }
        sVar5 = strlen("\n[+] Bye bye!\n");
        send(clientfd,"\n[+] Bye bye!\n",sVar5,0);
        close(clientfd);
                    /* WARNING: Subroutine does not return */
        exit(0);
      }
    }
    if (!bVar2) {
      bVar2 = true;
    }
    if (((numentries == 0) || (string_head == (string *)0x0)) ||
       (iVar4 = checkForTermination(p.datafield_1,0x10), iVar4 != 0)) {
      puts("Warning: There are no coordinates left to delete");
    }
    else {
      previous = (string *)0x0;
      for (current = string_head; current != (string *)0x0; current = current->next) {
        iVar4 = strcmp(p.datafield_1,current->buffer);
        if (iVar4 == 0) {
          puts("Deleted requested coordinate");
          if (current == string_head) {
            string_head = string_head->next;
          }
          else {
            previous->next = current->next;
          }
          free(current);
          break;
        }
        previous = current;
      }
    }
    if (((numentries == 0) || (number_head == (number *)0x0)) ||
       (iVar4 = checkForTermination(p.datafield_2,8), iVar4 != 0)) {
      puts("Warning: There are no radiation values left to delete");
    }
    else {
      current_1 = number_head;
      previous_1 = (number *)0x0;
      _Var7 = __bswap_64((__uint64_t)p.datafield_2);
      for (; current_1 != (number *)0x0; current_1 = current_1->next) {
        if (current_1->num == _Var7) {
          puts("Deleted requested radiation value");
          if (current_1 == number_head) {
            number_head = number_head->next;
          }
          else {
            previous_1->next = current_1->next;
          }
          free(current_1);
          break;
        }
        previous_1 = current_1;
      }
    }
    numentries = numentries + -1;
  } while( true );
}
```

I later ran into issues with the `action` portion of the packet. This, as it turns out, was in network byte order.

```
void parse_packet(packet *p,uchar *payload)

{
  uint16_t uVar1;
  int iVar2;
  int temp;
  
  iVar2 = validate(payload);
  if (iVar2 != 0) {
    p->payload_ip = *(int *)payload;
    *(undefined2 *)&p->payload_port = *(undefined2 *)(payload + 5);
    p->timestamp = *(int *)(payload + 8);
    *(undefined2 *)&p->action = *(undefined2 *)(payload + 0xd);
    uVar1 = htons((uint16_t)p->action);
    p->action = (uint)uVar1;
    *(undefined4 *)p->datafield_1 = *(undefined4 *)(payload + 0x10);
    *(undefined4 *)(p->datafield_1 + 4) = *(undefined4 *)(payload + 0x15);
    *(undefined4 *)(p->datafield_1 + 8) = *(undefined4 *)(payload + 0x1a);
    *(undefined4 *)(p->datafield_1 + 0xc) = *(undefined4 *)(payload + 0x1f);
    *(undefined8 *)p->datafield_2 = *(undefined8 *)(payload + 0x24);
  }
  return;
}
```

Notice: `htons`.

#### Looting

My final answer looks like so:

```
$ cat message.py     
from pwn import *
import struct
import datetime
import socket
import time

string_payloads_from_client = []
# first capture
string_payloads_from_client.append("ac16ec2c0e270f0e636580b00e00010e444e31330e766f00000e000000000e000000000e00000000000001400e0c")
string_payloads_from_client.append("ac16ec2c0e270f0e636580b00e00010e484d31330e566f00000e000000000e000000000e00000000000000390e0c")
string_payloads_from_client.append("ac16ec2c0e270f0e636580b00e00050e000000000e000000000e000000000e000000000e00000000000000000e0c")
# second capture
string_payloads_from_client.append("ac16ec2c0e270f0e636581d40e00010e444d30360e637300000e000000000e000000000e00000000000000780e0c")
string_payloads_from_client.append("ac16ec2c0e270f0e636581d40e00030e000000000e000000000e000000000e000000000e00000000000000000e0c")
string_payloads_from_client.append("ac16ec2c0e270f0e636581d40e00050e000000000e000000000e000000000e000000000e00000000000000000e0c")

def decode_client_request_packet(binary_request):
    idk = struct.unpack('>Ic Hc Ic Hc 4sc 4sc 4sc 4sc 8sc c', bytearray.fromhex(binary_request))
    client_ip_decimal = idk[0]
    client_ip = socket.inet_ntoa(p32(client_ip_decimal))
    client_port = idk[2]
    that_timestamp = idk[4]
    human_readable_datetime = datetime.datetime.fromtimestamp(that_timestamp)
    action = idk[6]
    datafield_1 = idk[8] + idk[10] + idk[12] + idk[14]
    datafield_2 = idk[16]
    print(client_ip, client_port, human_readable_datetime, action, datafield_1, datafield_2)

for payload in string_payloads_from_client:
    print(payload)
    decode_client_request_packet(binary_request=payload)

def make_datafield_1(datafield_1_content):
    n = 4
    delimiter = b"\x0e"
    padding = b"\x00" * (16 - len(datafield_1_content))
    datafield_1_content += padding
    datafield_1 = bytearray(b"\x00" * ((n * 4) + n)) 
    chunks = [datafield_1_content[i:i+n] for i in range(0, len(datafield_1_content), n)]
    offset = 0
    for my_chunk in chunks:
        struct.pack_into("<4sc", datafield_1, offset, my_chunk, delimiter)
        offset += n+1
    return datafield_1

def craft_packet(payload_ip, payload_port, timestamp, action, datafield_1_contents, datafield_2_contents):
    delimiter = "\x0e"
    formfeed = "\x0c"
    # payload_ip is a decimal representation of IPv4
    payload_ip = p32(payload_ip)
    payload_port = p16(payload_port)
    # timestamp is unix epoch time
    timestamp = p32(timestamp)
    # for some reason gets turned into 2^(action) serverside
    action = p16(socket.ntohs(action))
    datafield_1 = make_datafield_1(datafield_1_contents)
    datafield_2 = bytearray(b"\x00" * 8)
    struct.pack_into("<" + str(len(datafield_2_contents)) + "s", datafield_2, 8 - len(datafield_2_contents), datafield_2_contents)
    if len(datafield_1) > (16+4) or len(datafield_2) > 8:
        print("datafield too long")
        exit(1)
    return flat([
        payload_ip,
        delimiter,
        payload_port,
        delimiter,
        timestamp,
        delimiter,
        action,
        delimiter,
        datafield_1, # we pack in a delimiter inside it
        datafield_2,
        delimiter,
        formfeed
    ], filler = b'\x00', endianness="little")

# conn = remote('127.0.0.1', 9999)
conn = remote('trellixhax-free-yo-radicals-part-i.chals.io', 443, ssl=True)
line = conn.recvline()
print(line)

def response_cycle(conn, sendme):
    print(sendme.hex())
    conn.send(sendme)
    line = conn.recvline()
    print(line)
    line = conn.recvline()
    print(line)
    sleep(1)
    line = conn.recvline()
    print(line)

this_time = int(time.time())

my_packet = craft_packet(
    payload_ip=2130706433, # decimal ip for 127.0.0.1
    payload_port=443,
    timestamp=this_time, # unix epoch
    action=1,
    datafield_1_contents=b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
    datafield_2_contents=b"\x10\x10\x10\x10\x10\x10\x10\x10"
)
response_cycle(conn, my_packet)

my_packet = craft_packet(
    payload_ip=2130706433, # decimal ip for 127.0.0.1
    payload_port=443,
    timestamp=this_time, # unix epoch
    action=2,
    datafield_1_contents=b"",
    datafield_2_contents=b""
)
response_cycle(conn, my_packet)

my_packet = craft_packet(
    payload_ip=2130706433, # decimal ip for 127.0.0.1
    payload_port=443,
    timestamp=this_time, # unix epoch
    action=3,
    datafield_1_contents=b"",
    datafield_2_contents=b""
)
response_cycle(conn, my_packet)

my_packet = craft_packet(
    payload_ip=2130706433, # decimal ip for 127.0.0.1
    payload_port=9999,
    timestamp=this_time, # unix epoch
    action=5,
    datafield_1_contents=b"",
    datafield_2_contents=b""
)
response_cycle(conn, my_packet)
```

This will pwn it for you automatically.