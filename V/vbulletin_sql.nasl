#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14785);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2004-2695");
  script_bugtraq_id(11193);

  script_name(english:"vBulletin authorize.php x_invoice_num Parameter SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
SQL injection attack.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of vBulletin is vulnerable
to a SQL injection issue.  It is reported that versions 3.0.0 through
to 3.0.3 are prone to this issue.  An attacker may exploit this flaw
to gain the control of the remote database.");
  script_set_attribute(attribute:"see_also", value:"http://www.vbulletin.com/forum/showthread.php?p=734250#post734250");
  script_set_attribute(attribute:"see_also", value:"https://www.vbulletin.com/forum/forum/vbulletin-announcements/vbulletin-announcements_aa/127990-vbulletin-3-0-4-released?t=124876");
  script_set_attribute(attribute:"solution", value:
"Upgrade to vBulletin 3.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vbulletin:vbulletin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_dependencies("vbulletin_detect.nasl");
  script_require_keys("www/vBulletin");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if ( ver =~ '^3.0(\\.[0-3])?[^0-9]' )
  {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }
}
