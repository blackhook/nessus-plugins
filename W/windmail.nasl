#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
 script_id(10365);
 script_version("1.33");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

 script_cve_id("CVE-2000-0242");
 script_bugtraq_id(1073);

 script_name(english:"Windmail.exe Shell Metacharacter Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of windmail.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to arbitrary
command execution.");
 script_set_attribute(attribute:"description", value:
"The remote host may be running WindMail as a CGI application. In this
mode, some versions of the 'windmail.exe' script allow an attacker to
execute arbitrary commands on the remote server.");
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2000/Mar/322");
 script_set_attribute(attribute:"solution", value:"Remove the CGI script.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/03/25");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/04/12");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2021 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if ( ! banner || "Server: Microsoft/IIS" >!< banner ) exit(0);

res = is_cgi_installed3(item:"windmail.exe", port:port);
if(res)security_hole(port);
