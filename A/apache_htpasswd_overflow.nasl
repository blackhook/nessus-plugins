#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14771);
 script_version("1.25");
 script_cvs_date("Date: 2018/11/15 20:50:25");

 script_bugtraq_id(13777, 13778);
 script_xref(name:"EDB-ID", value:"466");

 script_name(english:"Apache <= 1.3.33 htpasswd Local Overflow");
 script_summary(english:"Checks for Apache <= 1.3.33");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Apache 1.3.33 or older.

There is a local buffer overflow in the 'htpasswd' command in these
versions that may allow a local user to gain elevated privileges if
'htpasswd' is run setuid or a remote user to run arbitrary commands
remotely if the script is accessible through a CGI.

*** Note that Nessus solely relied on the version number *** of the
remote server to issue this warning. This might *** be a false
positive");
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2004/Oct/356");
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2004/Sep/565" );
 script_set_attribute(attribute:"solution", value:
"Make sure htpasswd does not run setuid and is not accessible through
any CGI scripts.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/17");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2018 Tenable Network Security, Inc.");

 script_family(english:"Web Servers");

 script_dependencies("apache_http_version.nasl");
 script_require_keys("installed_sw/Apache", "Settings/ParanoidReport");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:"Apache", port:port, exit_if_unknown_ver:TRUE);

banner = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);
serv = strstr(banner, "Server:");
if(!serv) exit(0);

if(preg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-1][0-9]|2[0-9]|3[0-3])))", string:serv))
{
	security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);
