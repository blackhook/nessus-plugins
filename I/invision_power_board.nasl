#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11273);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2003-1385");
  script_bugtraq_id(6976, 7204);

  script_name(english:"Invision Power Board ipchat.php root_path Parameter Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a remote
file inclusion attack.");
  script_set_attribute(attribute:"description", value:
"It is possible to make the remote host include PHP files hosted on a
third-party server using Invision Power Board. The ipchat.php script 
fails to sanitize input passed to the 'root_path' parameter.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server. 

In addition, the ad_member.php script has been reported vulnerable. 
However, Nessus has not checked for that script.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/vulnwatch/2003/q1/99");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2003-1385");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/02/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:invisionpower:invision_power_board");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("invision_power_board_detect.nasl");
  script_require_keys("www/PHP");
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
if(!can_host_php(port:port))exit(0);


# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/invision_power_board"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    dir = matches[2];

    w = http_send_recv3(item:string(dir, "/ipchat.php?root_path=http://example.com/"), method:"GET", port:port);
    if (isnull(w)) exit(1, "The web server did not answer");
    r = w[2];
    if(egrep(pattern:".*http://example.com/conf_global.php.*", string:r))
    {
      security_hole(port);
      exit(0);
    }
  }
}
