#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(18536);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/06");

 script_name(english:"CA eTrust Intrusion Detection System Detection");

 script_set_attribute(attribute:"synopsis", value:
"An intrusion detection system is listening on the remote port." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the CA eTrust Intrusion
Detection System service." );
 script_set_attribute(attribute:"solution", value:
"Make sure this service is used in accordance with your corporate
security policy. 

If this service is not needed, disable it or filter incoming traffic
to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/21");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:etrust_intrusion_detection");
script_end_attributes();

 script_summary(english:"CA eTrust Intrusion Detection System detection");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Service detection");
 script_require_ports(9191);
 exit(0);
}

include("crypto_func.inc");


# data length must be % 8
function _blowfish_decrypt (data)
{
 local_var i, tmp, to_decrypt;

 tmp = NULL;

 for (i = 0;i < strlen(data); i += 8)
 {
  to_decrypt = substr (data, i, i+7);
  tmp += blowfish_decipher (data:to_decrypt);
 }

 return tmp;
}


# data length must be % 8
function _blowfish_encrypt (data)
{
 local_var i, tmp, to_encrypt;

 tmp = NULL;

 for (i = 0;i < strlen(data); i += 8)
 {
  to_encrypt = substr (data, i, i+7);
  tmp += blowfish_encipher (data:to_encrypt);
 }

 return tmp;
}

# script code starts here

port = 9191;

if ( ! get_port_state(port) ) exit(0);



soc = open_sock_tcp (port);
if (!soc)
  exit (0);

blowfish_initialize (key:"zdkv/032ihr");

first_packet = raw_string (0x01,0x02,0x00,0x00,0x00,0x54,0x4E,0x53);
enc = _blowfish_encrypt (data:first_packet);
packet = raw_string (strlen(enc) + 2) + raw_string (0x80) + enc;

send (socket:soc, data:packet);
buf = recv (socket:soc, length:100);

if ((strlen(buf) < 2) || (ord(buf[1]) != 0x80))
  exit (0);

len = ord(buf[0]);
if (strlen(buf) != len)
  exit (0);

enc = substr (buf, 2, strlen(buf)-1);
dec = _blowfish_decrypt (data:enc);
if ( strlen(dec) < 17 ) exit(0);

vers1 = ord(dec[16]);
vers2 = ord(dec[15]);
vers3 = ord(dec[13]) + ord(dec[14])*256;

vers = strcat(vers1,".",vers2,".",vers3);

report = strcat('\n',
  "The remote host is running eTrust Intrusion Detection System v",
  vers);

register_service(port:port, proto:"eTrust-IDS");
security_note (port:port, extra:report);
set_kb_item (name:"eTrust/intrusion_detection_system", value:vers);
