#%NASL_MIN_LEVEL 70300
#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, touched up description block (6/10/09)
# - Replaced broken URLs and added patch date (3/7/13)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10854);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2001-1217");
  script_bugtraq_id(3727);

  script_name(english:"Oracle 9iAS mod_plsql Encoded Traversal Arbitrary File Access");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary files can be read on the remote host.");
  script_set_attribute(attribute:"description", value:
"In a default installation of Oracle 9iAS, it is possible 
to use the mod_plsql module to perform a directory traversal 
attack. This allows attackers to read arbitrary files on
the server.");
  # http://web.archive.org/web/20030820210534/http://otn.oracle.com/deploy/security/pdf/modplsql.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e6ebd76");
  # http://web.archive.org/web/20020213012636/http://www.nextgenss.com/advisories/plsql.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6231377");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/index.html");
  script_set_attribute(attribute:"solution", value:
"Download the patch from the oracle metalink site.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2001/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/02/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2002-2022 Matt Moore");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_keys("www/OracleApache");
  script_require_ports("Services/www", 80);

  exit(0);
}

# Check starts here

include("http_func.inc");
include("global_settings.inc");

port = get_http_port(default:80, embedded:TRUE);

if(get_port_state(port))
{ 
# Make a request for the Admin_ interface.
 req = http_get(item:"/pls/sample/admin_/help/..%255cplsql.conf",
 		port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("Directives added for mod-plsql" >< r)	
 	security_warning(port);

 }
}
