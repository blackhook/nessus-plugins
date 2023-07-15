#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15762);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2004-1535");
  script_bugtraq_id(11701);

  script_name(english:"phpBB Cash_Mod admin_cash.php Arbitrary Command Execution");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server.");
  script_set_attribute(attribute:"description", value:
"It is possible to make the remote host include PHP files hosted on a
third-party server using the phpBB CGI suite which is installed. 

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.");
  script_set_attribute(attribute:"solution", value:
"Upgrade phpBB to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2004-1535");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpbb_group:phpbb");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("phpbb_detect.nasl");
  script_require_keys("www/phpBB");
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

kb = get_kb_item("www/" + port + "/phpBB");
if ( ! kb ) exit(0);
if(!can_host_php(port:port))exit(0);


matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
loc = matches[2];

r = http_send_recv3(method:"GET", item:strcat(loc, "/admin/admin_cash.php?setmodules=1&phpbb_root_path=http://example.com/"), port:port);      
if (isnull(r)) exit(0);
buf = strcat(r[0], r[1], '\r\n', r[2]);
if(egrep(pattern:".*http://example.com/includes/functions_cash\.", string:buf))
 {
   security_hole(port);
   exit(0);
 }
