#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10480);
 script_version("1.35");
 script_cvs_date("Date: 2018/11/15 20:50:25");

 script_cve_id("CVE-2000-0628");
 script_bugtraq_id(1457);

 script_name(english:"Apache ASP module Apache::ASP source.asp Example File Arbitrary File Creation");
 script_summary(english:"Checks for the presence of /site/eg/source.asp");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an arbitrary file creation
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The file /site/eg/source.asp is present on the remote Apache web
server.

This file comes with the Apache::ASP package and allows anyone to
write to files in the same directory. An attacker may use this flaw to
upload his own scripts and execute arbitrary commands on this host.");
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2000/Jul/142");
 script_set_attribute(attribute:"solution", value:"Upgrade to Apache::ASP 1.95 or newer.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/07/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/07/23");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:joshua_chamas:apache_asp");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000-2018 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencies("apache_http_version.nasl");
 script_require_keys("installed_sw/Apache", "Settings/ParanoidReport");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:"Apache", port:port);

res = is_cgi_installed3(port:port, item:"/site/eg/source.asp");
if( res )
{
 security_hole(port);
}
else
{
 audit(AUDIT_INST_VER_NOT_VULN, "Apache");
}
