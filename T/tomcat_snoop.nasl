#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
 script_id(10478);
 script_version("1.30");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

 script_cve_id("CVE-2000-0760");
 script_bugtraq_id(1532);

 script_name(english:"Apache Tomcat Snoop Servlet Remote Information Disclosure");
 script_summary(english:"Checks for the presence of /examples/jsp/snp/anything.snp");

 script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat web server has a servlet installed that is
affected by an information disclosure vulnerability.");
 script_set_attribute(attribute:"description", value:
"The 'snoop' Tomcat servlet is installed. This servlet gives too much
information about the remote host, such as the PATHs in use, the host
kernel version, etc.

A remote attacker can exploit this to gain more knowledge about the
host, allowing an attacker to conduct further attacks.");
 script_set_attribute(attribute:"solution", value:"Delete the 'snoop' servlet.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"vuln_publication_date", value:"2000/07/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/07/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2021 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencies("tomcat_error_version.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("installed_sw/Apache Tomcat");

 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("install_func.inc");

get_install_count(app_name:"Apache Tomcat", exit_if_zero:TRUE);
port = get_http_port(default:8080);
install = get_single_install(app_name:"Apache Tomcat", port:port);

res = http_send_recv3(method:"GET", item:"/examples/jsp/snp/anything.snp", port:port);

if(preg(pattern:"HTTP/[0-9]\.[0-9] 200 ", string:res[2]))
{
   security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache Tomcat", port, install["version"]);

