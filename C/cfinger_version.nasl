#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10651);
 script_version ("1.13");
 script_name(english:"cfingerd Version Detection");
 script_summary(english:"cfingerd version");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"A finger daemon is running on the remote host."
 );
 script_set_attribute(attribute:"description",  value:
"Nessus was able to detect the version of cfingerd running on the
remote host." );
 script_set_attribute( attribute:"solution",  value:
"Make sure the use of this software is in accordance with your
corporate security policy." );
 script_set_attribute(
   attribute:"risk_factor", 
   value:"None"
 );
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/04/16");
 script_cvs_date("Date: 2019/11/22");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");
 
 script_copyright(english:"This script is Copyright (C) 2001-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencie("find_service1.nasl");
 script_require_ports("Services/finger", 79);

 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/finger");
if(!port)port = 79;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = string("version\r\n");
  send(socket:soc, data:buf);
  r = recv(socket:soc, length:4096);
  if("CFINGERD" >< r)
  {
    s = strstr(r, "CFINGERD");
    version = ereg_replace(pattern:"(.*) is (.*[0-9]).*$",
    			  string:s,
			   replace:"\2");
			   
   report = string("cfingerd version : ", version);
   set_kb_item(name:"cfingerd/version",
   		value:version); 
   security_note(port:port, extra:report);
  }
  close(soc);
  }
}
