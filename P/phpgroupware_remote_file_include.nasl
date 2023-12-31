#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14294);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(8265);

  script_name(english:"phpGroupWare Unspecified Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host.");
  script_set_attribute(attribute:"description", value:
"The version of PhpGroupWare hosted on the remote web server has a
vulnerability that may permit remote attackers, without prior
authentication, to include and execute malicious PHP scripts. 

Remote users may influence URI variables to include a malicious PHP 
script on a remote system, it is possible to cause arbitrary PHP code to
be executed.");
  script_set_attribute(attribute:"solution", value:
"Update to phpGroupWare version 0.9.14.006 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpgroupware:phpgroupware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_dependencies("phpgroupware_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80, embedded:TRUE);

kb = get_kb_item("www/" + port + "/phpGroupWare");
if (! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
if ( ereg(pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-3]\.|14\.0*[0-5]([^0-9]|$)))", string:matches[1]) )
	security_hole(port);
