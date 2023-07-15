#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  From: "Frog Man" <leseulfrog@hotmail.com>
#  To: vulnwatch@vulnwatch.org, bugtraq@securityfocus.com
#  Subject: [VulnWatch] myPHPCalendar : Informations Disclosure, File Include


include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
  script_id(11877);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2006-6812");

  script_name(english:"myPHPcalendar Multiple Scripts cal_dir Parameter Remote File Inclusion");
  script_summary(english:"Checks for the presence of contacts.php");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected
by a remote file include vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote web server appears to be hosting myPHPCalender. The 
installed version contains a vulnerability that could allow an
attacker to make the remote host include php files hosted on a third
party server.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server." );
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/vulnwatch/2003/q4/10" );
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-6812");

  script_set_attribute(attribute:"plugin_publication_date", value: "2003/10/12");
  script_set_attribute(attribute:"vuln_publication_date", value: "2003/10/12");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CGI abuses");

  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);


function check(url)
{
  local_var res;

  res = http_send_recv3(method:"GET", item:string(url, "/contacts/php?cal_dir=http://example.com/"), port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  if("http://example.com/vars.inc" >< res[2])
  {
    security_hole(port);
    exit(0);
  }
}

foreach dir (cgi_dirs())
 check(url:dir);
