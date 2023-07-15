#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
 script_id(11610);
 script_version("1.25");
 script_cve_id("CVE-2003-1531");
 script_bugtraq_id(7214);

 script_name(english:"Ceilidh testcgi.exe query Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a CGI installed that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host has a CGI called 'testcgi.exe' installed
under /cgi-bin that is vulnerable to a cross-site scripting
issue." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a newer version." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(79);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/09");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determine if testcgi.exe is vulnerable to xss");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2003-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, no_xss: 1);
test_cgi_xss( port: port, cgi: '/testcgi.exe', qs: '<script>x</script>', 
	      pass_str: "<script>x</script>" );
