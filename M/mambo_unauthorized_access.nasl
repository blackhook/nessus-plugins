#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16312);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(12436);

  script_name(english:"Mambo Global Variables Unauthorized Access");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows
unauthorized access to the affected website.");
  script_set_attribute(attribute:"description", value:
"The remote version of Mambo Open Source contains a vulnerability that
could allow a remote attacker to gain unauthorized access to the 
system. This arises due to improper implementation of global variables 
and not sanitizing user-supplied input.");
  # https://web.archive.org/web/20050430140551/http://forum.mamboserver.com/showthread.php?t=29960
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da797297");
  script_set_attribute(attribute:"see_also", value:"http://www.mamboportal.com/content/view/2008/2/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to patched version 4.5.1b.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE available for this vulnerability.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mambo:mambo");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mambo_detect.nasl");
  script_require_keys("www/mambo_mos");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0, "The web server on port "+port+" does not support PHP");


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0, "Mambo is not installed on port "+port);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];

 w = http_send_recv3(method:"GET", item:string(dir, "/index.php?GLOBALS[mosConfig_absolute_path]=http://example.com"), port:port);
 if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
 r = w[2];
 if( "http://example.com/includes/HTML_toolbar.php" >< r )
 	security_hole(port);
}
