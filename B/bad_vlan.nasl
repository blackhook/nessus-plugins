#TRUSTED 020caee29478550da2dac39ed783b51dfe4d19918dc93465312df249aef761a3aa860a1313becfaeed31ffc6cefd751bcf0ec26e9c8584325047a36ce7dd1e0fc22277a9c6573de98cb1de7ce0a011112e9df197cb99bac9f83b19a5a289b3f5d5888c6fb9c6fa834695c98b4b516211147b0e19b97be7f13f92265dd4b32ae9d796b7bab3c18a48add3cb65ba9cf3c1c6ff7c5808c0ca9036cff2da8f7fe6f3fef8e649a3982dfd6c9acfa06cfe483201a4223cc43a2f207a7a34e0ccd160a425105fa37e4eafa60dc8a26255d255809cebd6e63820338ae4769d2c4933dd5182c7514ea9fcb65eb3d3e926981f6ad847f6d8760d5e0774564e5f0fb3d28ea420bd468ef72da85b080eae0500140d8019300698dc763299471adef4b2fe2330c39d340f5f3134d28704e9cd7bccb759fd36ad104eddc65c080cbe810f6875af6fa29a330b457d3a358fa2839eb99c58c4278a2444810fc0b02874f348470936e71ac9d8854be5bdb8f02b29170296850fd67e8c04007028122e9df026ec15d0a29f825dcf9f141880c5104216f57d2bfa8bcd58f29cefd95239d5d93bb5da83b26605e91088ad9ad0fcded238ab2a97ede0ba3dca001256ca4df81a5006d1162be0c5188fb9082b5500be6138bb0b0361d90d89aca0c08c6365240b20875d35d12dfb07d02a670d8c7b1f96c4527e77cadd6ac7f04ae2d9530898a906ea5a62
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if(description)
{
  script_id(23971);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Host Logical Network Segregation Weakness");

  script_set_attribute(attribute:"synopsis", value:
"The physical network is set up in a potentially insecure way.");
  script_set_attribute(attribute:"description", value:
"The remote host is on a different logical network than the
Nessus scanner. However, it is on the same physical subnet.

An attacker connecting from the same network as your Nessus
scanner could reconfigure his system to force it to belong
to the subnet of the remote host.

This may allow an attacker to bypass network filtering between
the two subnets.");
  script_set_attribute(attribute:"solution", value:
"Use VLANs to separate different logical networks.");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2007-2022 Tenable Network Security, Inc.");


  exit(0);
}


#


# ByteFunc included here
BYTE_ORDER_BIG_ENDIAN  		= 1;
BYTE_ORDER_LITTLE_ENDIAN 	= 2;

ByteOrder = BYTE_ORDER_BIG_ENDIAN;

function set_byte_order()
{
 ByteOrder = _FCT_ANON_ARGS[0];
}

function mkbyte()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];
 return raw_string(l & 0xff);
}

function mkword()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];

 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
 	return  raw_string((l >> 8) & 0xFF, l & 0xFF);
 else
 	return  raw_string(l & 0xff, (l >> 8) & 0xff);
}


function mkdword()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];

 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
	 return  raw_string( (l >> 24 ) & 0xff,
		     	     (l >> 16 ) & 0xff,
		     	     (l >>  8 ) & 0xff,
		     	     (l)   & 0xff);
 else
	 return  raw_string( l & 0xff,
		     	    (l >> 8) & 0xff,
		            (l >> 16) & 0xff,
		            (l >> 24)   & 0xff);
}


function getdword(blob, pos)
{
 local_var l, s;
 if ( strlen(blob) < pos + 4 )
	return NULL;

 s = substr(blob, pos, pos + 3);
 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
  return ord(s[0]) << 24 | ord(s[1]) << 16 | ord(s[2]) << 8 | ord(s[3]);
 else
  return ord(s[0]) | ord(s[1]) << 8 | ord(s[2]) << 16 | ord(s[3]) << 24;
}

function getword(blob, pos)
{
 local_var l, s;
 if ( strlen(blob) < pos + 2 )
	return NULL;
 s = substr(blob, pos, pos + 1);
 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
  return ord(s[0]) << 8 | ord(s[1]);
 else
  return ord(s[0]) | ord(s[1]) << 8;
}

function getbyte(blob, pos)
{
 local_var l, s;
 if ( strlen(blob) < pos + 1 )
	return NULL;
 s = substr(blob, pos, pos);
 return ord(s[0]);
}




function mkpad()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];
 return crap(data:raw_string(0), length:l);
}





function mkipaddr()
{
 local_var ip;
 local_var str;

 ip = _FCT_ANON_ARGS[0];
 str = split(ip, sep:'.', keep:FALSE);
 return raw_string(int(str[0]), int(str[1]), int(str[2]), int(str[3])); 
}


function is_class_b(a,b)
{
 local_var aa, ab;
 local_var i;

 aa = split(a, sep:'.', keep:FALSE);
 ab = split(b, sep:'.', keep:FALSE);
 
 for ( i = 0 ; i < 4 ; i ++ )
 {
   if ( aa[i] != ab[i] ) break;
 }

 if ( i < 2 ) return FALSE;
 else return TRUE;
}


function arp_ping()
{
 local_var broadcast, macaddr, arp, ethernet, i, r, srcip, dstmac;

 broadcast = crap(data:raw_string(0xff), length:6);
 macaddr   = get_local_mac_addr();

 if ( ! macaddr ) return 0;  # Not an ethernet interface

 arp       = mkword(0x0806); 
 ethernet = broadcast + macaddr + arp;
 arp      = ethernet +              			# Ethernet
           mkword(0x0001) +        			# Hardware Type
           mkword(0x0800) +        			# Protocol Type
           mkbyte(0x06)   +        			# Hardware Size
           mkbyte(0x04)   +        			# Protocol Size
           mkword(0x0001) +        			# Opcode (Request)
           macaddr        +        			# Sender mac addr
           mkipaddr(compat::this_host()) + 			# Sender IP addr
           crap(data:raw_string(0), length:6) + 	# Target Mac Addr
           mkipaddr(get_host_ip());

 for ( i = 0 ; i < 2 ; i ++ )
 {
  r = inject_packet(packet:arp, filter:"arp and arp[7] = 2 and src host " + get_host_ip(), timeout:1);
  if ( ! r || strlen(r) <= 31 ) continue;
  srcip = substr(r, 28, 31);
  if ( srcip == mkipaddr(get_host_ip() ) )
   {
    dstmac = substr(r, 6, 11);
    dstmac = strcat(hexstr(dstmac[0]), ":",
	            hexstr(dstmac[1]), ":",
		    hexstr(dstmac[2]), ":",
		    hexstr(dstmac[3]), ":",
		    hexstr(dstmac[4]), ":",
		    hexstr(dstmac[5]));
    return dstmac;
   }
  }
}

# Nessus 3 only
if ( ! defined_func("inject_packet") ) exit(0);
if ( ! isnull(get_gw_mac_addr()) ) exit(0);

# If the target is officially in the same subnet, exit
if ( islocalnet() || TARGET_IS_IPV6 ) exit(0);

opt = get_kb_item("global_settings/thorough_tests");
if (! opt || "yes" >!< opt  )
	# If the target is not at least in the same class B, exit
	if ( ! is_class_b(a:compat::this_host(), b:get_host_ip() ) ) exit(0);



if ( mac = arp_ping() )
{
 if ( mac == get_gw_mac_addr() ) exit(0); # Arp proxy
 replace_kb_item(name:"ARP/mac_addr", value:mac);
 security_note(port:0,extra:"The MAC address of the remote host is " + mac );
}
