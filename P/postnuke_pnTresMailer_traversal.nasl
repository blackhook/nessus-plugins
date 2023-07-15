#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15858);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2004-1205", "CVE-2004-1206");
  script_bugtraq_id(11767);

  script_name(english:"PostNuke pnTresMailer codebrowserpntm.php Traversal Arbitrary File Access");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary files can be read on the remote server?");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of the pnTresMailer PostNuke module
which is vulnerable to a directory traversal attack.

An attacker may use this flaw to read arbitrary files on the remote
web server, with the privileges of the web server process.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this module.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pntresmailer:pntresmailer");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_dependencies("postnuke_detect.nasl");
  script_require_keys("www/postnuke");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/postnuke" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
dir = stuff[2];


if(!can_host_php(port:port))exit(0);

u = strcat(dir, "/codebrowserpntm.php?downloadfolder=pnTresMailer&filetodownload=../../../../../../../../../../../etc/passwd");
r = http_send_recv3(method: "GET", port: port, item: u);
if (isnull(r)) exit(0);
 
if (egrep(pattern:"root:.*:0:[01]:.*", string: r[0]+r[1]+r[2])) 
	security_warning (port, extra:
'\nThe following URL exhibits the flaw :\n\n', build_url(port: port, qs: u), '\n');
