#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
 script_id(10002);
 script_version("1.46");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

 script_cve_id("CVE-1999-0449");
 script_bugtraq_id(193);

 script_name(english:"Microsoft IIS advsearch.asp Direct Request Remote DoS");
 script_summary(english:"Determines the presence of an ExAir ASP");

 script_set_attribute(attribute:"synopsis", value:"The remote web server is prone to a denial of service attack.");
 script_set_attribute(attribute:"description", value:
"The remote instance of IIS includes the sample site 'ExAir'. By
calling one of the included Active Server Pages, specifically
'/iissamples/exair/search/advsearch.asp', an unauthenticated, remote
attacker may be cause the web server to hang for up to 90 seconds (the
default script timeout) if the default ExAir page and associated DLLs
have not been loaded into the IIS memory space. This can be used to
render the site unusable.");
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/1999/Jan/319");
 script_set_attribute(attribute:"solution", value:"Delete the 'ExAir' sample IIS site.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/01/26");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2021 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_keys("Settings/ParanoidReport", "www/ASP");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


cgi = "/iissamples/exair/search/advsearch.asp";
ok = is_cgi_installed3(item:cgi, port:port);
if(ok)security_warning(port);
