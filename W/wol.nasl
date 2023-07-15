#TRUSTED 7f0d3eec8b5d08f50b533ef3b99369b5fcc69c270e94a8274799e9c6184ab6f94571c24b8e5e54add0b29f2d1907d149b27c2c233af02d597f21a923c0b230debde056b0b7d9cddda3311c31bdfd95ef6dd00be9e7d58baf6e6f96ec32bd13ae0695861b4b790d4a9daf7709da853c19cf5ce9b781c23a82141a1f99975c0eac4e5992d732195d87247ebadf05c3494d1bdd5d3aae459940faa696e559687b7c10019cf7781084e01a1ca86ef191a28c8761c59b86206cfac2e3f327a90af93a594cc5c43eb056983cf9637107e9aade04b07a319e9ff6dc6c587c697b08740571e56072906f28cd19384355991bde970ef57c8fe8c77dae9397641815a23ed9e79b6434a40bf79d0e042de88caad41eab3b27b62e29ea0872872d3011f1e86d556f05d372c08e131e2a33f5245fda844fbb15a13463b4b621ff7dd4a5e312f0bfc669c3eee969d3a4581a48e57a81b53a822acb167fc60356a2b061845721e1c6730577680aaa566e31e521836ec9ca69430e939cfde8611c2d1f0b3c2c8b2a41e3285c65a261d44e57f0c47825dff66728d44aa6a0daf404c8cd0cbae1c5afd1ba01eed9f710fdcdd9c7e778473f6fb92295b10e894302fedc03e94a52bfb011c4db129d1bde98e7e3a939647fba45312cca23895aa5173505de86507da980a933de87bbcc7b4d8114a81a6a7877f332fc7397a3009ae5d836fc795844f193
#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 4200 ) exit(0);
include("compat.inc");

if(description)
{
 script_id(52616);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value: "2017/06/12");

 script_name(english:"Wake-on-LAN");
 script_summary(english:"Wakes up the remote systems");

 script_set_attribute(attribute:"synopsis", value:
"This script wakes the remote computers on the local LAN." );
 script_set_attribute(attribute:"description", value:
"This script will send a WoL (Wake-On-LAN) packet to each MAC address
listed in file uploaded via its preference. 

To use this feature :

  - The scanner must be located on the same physical subnet 
    as the targets.

  - The MAC addresses of the targets must be listed in a 
    text file supplied via the policy (Edit the policy -> 
    Advanced -> Wake-On-LAN). Each MAC address should be 
    supplied on a different line.

This script will cause Nessus to wait 5 minutes (or any value
configured) before starting the scan to give time to the remote
systems to wake up from sleep." );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Wake-on-LAN" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/10");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_family(english:"Settings");
 script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
 script_category(ACT_INIT);

 script_add_preference(name:"List of MAC addresses for Wake-on-LAN: ", type:"file", value:"");
 script_add_preference(name:"Time to wait (in minutes) for the systems to boot: ", type:"entry", value:"5");
 script_timeout(0);

 exit(0);
}

include("misc_func.inc");
include("raw.inc");

global_var broadcast, macaddr;

function wol()
{
 local_var line, str, magic, ethernet, payload, wol;

 line = chomp(str_replace(string:_FCT_ANON_ARGS[0], find:":", replace:""));
 if ( (strlen(line) % 2) != 0 )  return 0;
 str = hex2raw(s:line);
 if ( strlen(str) != 6 ) return 0;
 magic = crap(length:6, data:'\xff');
 magic += crap(length:17 * strlen(str), data:str);


 ethernet = broadcast + macaddr + mkword(0x0800);
 payload = mkpacket(ip(ip_p:IPPROTO_UDP), udp(uh_dport:9), payload(magic));

 wol = ethernet + payload;

 inject_packet(packet:wol);
 return 1;
}



if ( islocalhost() ) exit(0);
if ( !islocalnet() ) exit(0);

macs = script_get_preference_file_content("List of MAC addresses for Wake-on-LAN: ");
if ( isnull(macs) || strlen(macs) == 0 ) exit(0);

# Take into account the fact we may be connected to multiple NICs
iface = routethrough();
if ( isnull(iface) ) exit(0, "Could not determine which iface to use.");

mutex_name = "WoL/" + iface;


broadcast = crap(data:raw_string(0xff), length:6);
macaddr   = get_local_mac_addr();

to   = script_get_preference("Time to wait (in minutes) for the systems to boot: ");
if ( int(to) <= 0 ) to = 5;
else to = int(to);

mutex_lock(mutex_name);
if ( get_global_kb_item(mutex_name) )
{
 # The script already ran
 mutex_unlock(mutex_name);
 exit(0);
}

lines = split(macs);
count = 0;
foreach line ( lines )
{
 if ( wol(line) != 0 )
 { 
  count ++;
  usleep(20000);
 }
}

set_global_kb_item(name:mutex_name, value:TRUE);
if ( count > 0 ) 
 {
  # Let the remote systems boot up
  #
  # In order to prevent the systems that were in "sleep" mode to go back to sleep
  # while we wait for others to do a cold boot, we send a new WoL packet every 
  # minute
  #
  deadline = unixtime() + to * 60;
  for ( i = 0 ; i < to ; i ++ )
  {
   if ( unixtime() > deadline ) break;
   foreach line ( lines )
   {
    if ( wol(line) != 0 ) usleep(20000);
   }
   n = 60 - ((count * 20000) / 1000000);
   if ( n > 0 ) sleep(n);
  }
 }
mutex_unlock(mutex_name);
