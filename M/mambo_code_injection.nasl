#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(12025);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");
  script_bugtraq_id(9445);

  script_name(english:"Mambo mod_mainmenu.php mosConfig_absolute_path Parameter Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote file include vulnerability.");
  script_set_attribute(attribute:"description", value:
"There is a flaw in the installed version of Mambo Open Source that may
allow an attacker to execute arbitrary remote PHP code on this host
because it fails to sanitize input to the 'mosConfig_absolute_path' of
'modules/mod_mainmenu.php' before using it to include PHP code from
another file. 

Note that, for exploitation of this issue to be successful, PHP's
'register_globals' setting must be enabled.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2004/Jan/138");
  # http://sourceforge.net/project/shownotes.php?group_id=25577&release_id=205901
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?472f1d6d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mambo Open Source 4.5 Stable (1.0.2) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE available for this vulnerability.");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mambo_detect.nasl");
  script_require_keys("www/mambo_mos");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (! can_host_php(port:port) ) exit(0, "Server on port "+port+" does not support PHP");


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0, "Mambo is not installed on port "+port);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];

 w = http_send_recv3(method:"GET", item:string(dir, "/modules/mod_mainmenu.php?mosConfig_absolute_path=http://example.com"), port:port);
 if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
 res = w[2];
 if ("http://example.com/modules" >< res ) security_warning(port);
}
