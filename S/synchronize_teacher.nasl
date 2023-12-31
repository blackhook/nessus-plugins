#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(21218);
 script_version ("1.10");
 script_cvs_date("Date: 2019/10/01 11:24:12");
 script_name(english:"SynchronEyes Teacher Detection");

 script_set_attribute(attribute:"synopsis", value:
"A remote control software is running on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SMART Technologies SynchronEyes Teacher. 
This software allows teachers to remotely control student desktops." );
 script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it or filter incoming traffic
to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/13");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:smart_technologies:synchroneyes");
script_end_attributes();

 script_summary(english:"Determine if a remote host is running SynchronEyes Teacher");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 script_copyright(english:"This script is Copyright (C) 2006-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_require_ports (5461);
 exit(0);
}


include("byte_func.inc");
 
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

function put_string (s)
{
 local_var i, tmp, len;

 len = strlen(s);
 tmp = mkdword (len);

 for (i=0; i<len; i++)
   tmp += mkbyte (0) + s[i];

 return tmp;
}


function getstring (blob, pos)
{
 local_var tmp, len, i, ret;

 if (strlen(blob) < (pos+4))
   return NULL;

 len = getdword (blob:blob, pos:pos);
 if (strlen(blob) < (pos+4+(len*2)))
   return NULL;
 
 pos += 4;
 tmp = NULL;

 for (i=0; i<len; i++)
   tmp += blob[pos+i*2+1];

 return tmp;
}


function parse_packet (format, data)
{
 local_var len, pos, tmp, ret, i;

 len = strlen (data);
 ret = NULL;
 pos = 0;

 for (i=0; i<max_index(format); i++)
 {
  if (format[i] == 0)
  {
   if (len < (pos+4))
     return NULL;

   ret[i] = getdword (blob:data, pos:pos);
   pos += 4;
  }
  else if (format[i] == 2)
  {
   if (len < (pos+2))
     return NULL;

   ret[i] = getword (blob:data, pos:pos);
   pos += 2;
  }
  else if (format[i] == 1)
  {
   tmp = getstring (blob:data, pos:pos);
   if (isnull(tmp))
     return NULL;

   pos += strlen(tmp) * 2;
   ret[i] = tmp;
  }
 }

 return ret;
}

function recv_sync_pkt (socket)
{
 local_var buf, len;

 buf = recv (socket:socket, length:8, min:8);
 if (strlen(buf) != 8)
   return NULL;

 len = getdword (blob:buf, pos:0);

 buf = recv (socket:socket, length:len, min:len);
 if (strlen(buf) != len)
   return NULL;

 return buf;
}


function send_sync_pkt (data, socket)
{
 send (socket:socket, data:mkdword (strlen(data)) + mkdword (0) + data);
}


port = 5461;
#port = 5485;

soc = open_sock_tcp (port);
if (!soc)
  exit (0);

data = mkdword (0) + 
       mkdword (0) + 
       put_string (s:"ConnectionEstablishementEB802D36-7E45-4757-BABA-84C75016AD3A") + 
       mkdword (2) + 
       mkword (6) + 
       mkword (0) + 
       mkword (30) + 
       mkword (1) + 
       mkdword (0);

send_sync_pkt (data:data, socket:soc);

buf = recv_sync_pkt (socket:soc);
if (isnull(buf))
  exit (0);

ret = parse_packet (data:buf, format:make_list (0,0,1,0,0,0));
if (isnull(ret))
  exit (0);

if ("ConnectionEstablishement" >!<ret[2])
 exit (0);

buf = recv_sync_pkt (socket:soc);
if (isnull(buf))
  exit (0);

ret = parse_packet (data:buf, format:make_list (0,0,1,0,0,0,0,2,2,2,2,1,0));
if (isnull(ret))
  exit (0);

if ("ScreenGrabberMsgCategory" >!< ret[2])
  exit (0);

version = string (ret[7],".",ret[8],".",ret[9],".",ret[10]);

report = string ("\n",
		"The remote host is running SynchronEyes Teacher version ", version , "\n");

security_note(extra:report, port:port);
