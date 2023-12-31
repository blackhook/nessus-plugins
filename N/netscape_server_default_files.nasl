#%NASL_MIN_LEVEL 70300
#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Revised plugin title, changed family (1/22/2009)


include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
  script_id(12077);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Netscape Enterprise Server Default Files Present");

  script_set_attribute(attribute:"synopsis", value:
"Default files are installed on the remote web server.");
  script_set_attribute(attribute:"description", value:
"Default files were found on the Netscape Enterprise Server.

These files should be removed as they may help an attacker to guess the
exact version of the Netscape Server that is running on this host.");
  script_set_attribute(attribute:"solution", value:
"Remove those files.");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/02/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netscape:enterprise_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 David Kyger");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

warning = "The following default files were found:";

port = get_http_port(default:80, embedded:TRUE);


if(get_port_state(port))
 {
  pat1 = "Netscape Enterprise Server Administrator's Guide";
  pat2 = "Enterprise Edition Administrator's Guide";
  pat3 = "Netshare and Web Publisher User's Guide";

  fl[0] = "/help/contents.htm";
  fl[1] = "/manual/ag/contents.htm";

  for(i=0;fl[i];i=i+1) {
    req = http_get(item:fl[i], port:port);
    buf = http_keepalive_send_recv(port:port, data:req);
    if ( buf == NULL ) exit(0);
    if ((pat1 >< buf) || (pat2 >< buf) || (pat3 >< buf)) {
     warning = warning + string("\n", fl[i]);
     flag = 1;
     }
    }

    if (flag > 0) { 
     security_note(port:port, extra: warning);
    }
}
