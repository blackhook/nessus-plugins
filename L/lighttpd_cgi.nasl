#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(16475);
  script_version("1.17");
  script_cve_id("CVE-2005-0453");
  script_bugtraq_id(12567);
  script_xref(name:"GLSA", value:"200502-21");
 
  script_name(english:"lighttpd < 1.3.8 Null Byte Request CGI Script Source Code Disclosure");
  script_summary(english:"Checks for version of lighttpd HTTP server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure 
vulnerability." );
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of lighttpd running on the remote
host is prior to 1.3.8. It is, therefore, affected by an information
disclosure vulnerability. An unauthenticated, remote attacker can
exploit this vulnerability, by requesting a CGI script that is
appended by a '%00', to read the source of the script.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://article.gmane.org/gmane.comp.web.lighttpd/1171");
  script_set_attribute(attribute:"solution", value:
"Upgrade to lighttpd version 1.3.8 or later" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");


  script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/16");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/12");

  script_cvs_date("Date: 2018/07/12 19:01:16");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lighttpd:lighttpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2018 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");

  script_dependencies("lighttpd_detect.nasl");
  script_require_keys("installed_sw/lighttpd");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("vcf.inc");

appname = "lighttpd";
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80);
app_info = vcf::get_app_info(app:appname, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [{"fixed_version":"1.3.8"}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
