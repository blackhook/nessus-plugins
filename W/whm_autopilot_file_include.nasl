#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16070);
  script_version("1.19");
  script_cve_id("CVE-2004-1420", "CVE-2004-1421", "CVE-2004-1422");
  script_bugtraq_id(12119);

  script_name(english:"WHM AutoPilot < 2.5.20 Multiple Remote Vulnerabilities");
  script_summary(english:"Determines if WHM AutoPilot can include third-party files");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
several vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"The remote web server is running WHM AutoPilot, a script designed to
administer a web-hosting environment. 

The remote version of this software is vulnerable to various flaws
that may allow an attacker to execute arbitrary commands on the remote
host, obtain information about the remote host's PHP installation, and
launch cross-site scripting attacks." );
  script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00059-12272004" );
  script_set_attribute(attribute:"solution", value:"Upgrade to WHM AutoPilot version 2.5.20 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2004-1421");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/28");
  script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2004-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach d (cgi_dirs())
{
 url = string(d, "/inc/header.php/step_one.php?server_inc=http://example.com/");
 w = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(w)) exit(1, "The web server did not answer");
 res = strcat(w[0], w[1], '\r\n', w[2]);
 if ( "http://example.com/step_one_tables.php" >< buf )
 {
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
 }
}
