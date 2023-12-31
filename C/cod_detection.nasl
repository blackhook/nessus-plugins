#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if(description)
{
  script_id(33275);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Call Of Duty Server Detection");

  script_set_attribute(attribute:"synopsis", value:
"A game server has been detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a Call of Duty game server.");
  script_set_attribute(attribute:"see_also", value:"https://www.callofduty.com/hub");
  script_set_attribute(attribute:"solution", value:
"Make sure that the use of this program is done in accordance with your
corporate security policy. If this service is not needed, disable it
or filter incoming traffic to this port.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:activision:call_of_duty");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_udp_ports(28960, 28961);

  exit(0);
}

include("global_settings.inc");
include('misc_func.inc');
include('byte_func.inc');

foreach port (make_list(28960, 28961))
{
 if (service_is_unknown(port:port, ipproto:"udp") && get_udp_port_state(port))
  {
   sock = open_sock_udp(port);
   if ( ! sock ) exit(0);

   # Send getstatus request
   # 0xFF,0xFF,0xFF,0xFF, getstatus

   req = mkdword(0xffffffff) + "getstatus";

   send(socket:sock, data:req);
   res = recv(socket:sock, length:1024);

   if ( "statusResponse" >< res && 
     "Call of Duty" >< res
     )
    {
     report = NULL;

     res2 = split(res, sep:"\",keep:FALSE);
     for ( i = 1 ; i < max_index(res2) && i+1 < max_index(res2) ; i+=2 )
     {
       report += string( res2[i], " : ", res2[i+1] ,'\n');
     }

     if (report_verbosity && report )
      {
          report = string('\n',"The following is known about the remote COD server : ",'\n\n',
		     report) ;	
          register_service(port:port, ipproto:"udp", proto:"call-of-duty");
          security_note(port:port, proto:"udp", extra:report); 
      }
     else
     {
      register_service(port: port, ipproto:"udp", proto: "call-of-duty");
      security_note(port:port, proto:"udp"); 
     }
    if (!thorough_tests) exit(0);
   }
  }
}

