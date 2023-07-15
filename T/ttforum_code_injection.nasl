#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Ref: 
# Date: 9 May 2003 16:58:36 -0000
# From: Charles Reinold <creinold@hotmail.com>
# To: bugtraq@securityfocus.com
# Subject: ttcms and ttforum exploits
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11615);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2003-1458", "CVE-2003-1459");
  script_bugtraq_id(7542, 7543);

  script_name(english:"ttforum Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a PHP script that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running ttforum.

This set of CGI is vulnerable to various attacks which
may allow an attacker to execute arbitrary code on this
host or gain administrative privileges on this forum.");
  script_set_attribute(attribute:"solution", value:
"Disable this forum or upgrade to a fixed version");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2003-1458");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(89, 94);

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if(!can_host_php(port:port))exit(0,"The remote web server does not support PHP.");

# Loop through directories.
if (thorough_tests) dirs =  list_uniq(make_list("/modules/forum", "/ttforum", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach d (dir)
{
 url = string(d, '/index.php?board=10;action=news;ext=help;template=http://example.com');
 res = http_send_recv3(method:"GET", item:url, port:port);
 if(isnull(res) ) exit(1,"Null response to index.php request.");
 
 if("php_network_getaddresses: getaddrinfo" >< res[2])
   {
    security_hole(port);
    exit(0);
   }
}
