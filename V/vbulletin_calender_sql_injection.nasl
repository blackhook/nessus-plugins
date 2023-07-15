#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From:   a1476854@hotmail.com
# Subject: vBulletin Forum 2.3.xx calendar.php SQL Injection
# Date: January 5, 2004 9:32:15 PM CET
# To:   bugtraq@securityfocus.com
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11981);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2004-0036");
  script_bugtraq_id(9360);

  script_name(english:"vBulletin calendar.php eventid Parameter SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that suffers from a SQL
injection flaw.");
  script_set_attribute(attribute:"description", value:
"A vulnerability has been discovered in the 'calendar.php' script that
allows unauthorized users to inject SQL commands through the 'eventid'
parameter.  An attacker may use this flaw to gain the control of the
remote database.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2004/Jan/31");
  script_set_attribute(attribute:"see_also", value:"https://www.vbulletin.com/forum/forum/vbulletin-announcements/vbulletin-announcements_aa/93720-vbulletin-2-3-4-released?postid=588825#post93720");
  script_set_attribute(attribute:"solution", value:
"Upgrade to vBulletin 2.3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/06");

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

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 path = matches[2];
 r = http_send_recv3(method:"GET",item:string(path, "/calendar.php?s=&action=edit&eventid=1'"), port:port);
 if (isnull(r)) exit(0);
 res = r[2];

 if ( "SELECT allowsmilies,public,userid,eventdate,event,subject FROM calendar_events WHERE eventid = 1'" >< res )
 {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
 }
}
