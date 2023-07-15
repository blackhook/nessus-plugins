#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  From: "Frog Man" <leseulfrog@hotmail.com>
#  To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
#  Date: Thu, 15 May 2003 19:06:40 +0200
#  Subject: [VulnWatch] OneOrZero Security Problems (PHP)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11643);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2003-0303");
  script_bugtraq_id(7609, 7611);

  script_name(english:"OneOrZero Helpdesk tupdate.php sg Parameter SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a SQL
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running OneOrZero, an online helpdesk.

There are multiple flaws in this software that could allow 
an attacker to insert arbitrary SQL commands in the remote 
database, or even to gain administrative privileges on this 
host.");
  script_set_attribute(attribute:"solution", value:
"Unofficial patches are available at http://www.phpsecure.info");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0,"The remote host does not support PHP.");

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/help", "/support", "/supporter", "/support/helpdesk", "/helpDesk", "/helpdesk", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach d (dirs)
{
  res = http_send_recv3(method:"GET", item:d + "/supporter/tupdate.php?groupid=change&sg='", port:port);
  if( isnull(res) ) exit(1,"Null response to tupdate.php request.");
  if("SQL" >< res[2] && "' where id='" >< res[2])
  {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
   exit(0);
  }
}
