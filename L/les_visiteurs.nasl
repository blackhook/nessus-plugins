#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
  script_id(11911);
  script_version("1.28");
  script_cve_id("CVE-2003-1148");
  script_bugtraq_id(8902);

  script_name(english:"Les Visiteurs Multiple Remote File Inclusion");
  script_summary(english:"Les Visiteurs inc file upload");
  
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP application that is affected by
a remote file inclusion vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote 'Les Visiteurs' PHP scripts are vulnerable to a bug 
wherein any anonymous user can force the server to redirect to 
any arbitrary IP and download a potentially malicious include file.  

This can allow an attacker to upload and execute malicious
code on the web server." );
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2003/Oct/263" );
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.0.2 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:W/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2003-1148");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value: "2003/10/27");
  script_set_attribute(attribute:"vuln_publication_date", value: "2003/10/25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:les_visiteurs:les_visiteurs");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CGI abuses");

  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  exit(0);
}

# start the test

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

foreach dir (cgi_dirs())
{
  res = http_send_recv3(method:"GET", item:string(dir, "/new-visitor.inc.php?lvc_include_dir=http://example.com"), port:port, exit_on_fail: 1);
 
  if ( egrep(pattern:"http://example.com/config\.inc\.php", string:res[2]) ) 
  {
    security_hole(port);
    exit(0);
  }
}
