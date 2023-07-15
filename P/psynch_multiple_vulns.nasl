#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.



include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(11694);
 script_version("1.22");
 script_bugtraq_id(7740, 7745, 7747);

 script_name(english:"P-Synch Password Management Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote web server is running P-Synch, a password management system
running over HTTP.

There is a flaw in the CGIs nph-psa.exe and nph-psf.exe which may allow
an attacker to make this host include remote files, disclose the path to
the p-synch installation or produce arbitrary HTML code (cross-site 
scripting)." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of P-Synch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/29");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "P-Synch issues");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "no404.nasl", "webmirror.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0, no_xss: 1);

dirs = list_uniq(make_list("/psynch", cgi_dirs()));

foreach cgi (make_list("/nph-psa.exe", "/nph-psf.exe"))
  test_cgi_xss( port: port, cgi: cgi, qs: 'css="><script>test</script>',
  		dirs: dirs, pass_str: "<script>test</script>" );
