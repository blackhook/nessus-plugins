#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63094);
  script_version("1.10");
  script_cvs_date("Date: 2018/07/12 19:01:16");

  script_cve_id("CVE-2012-5533");
  script_bugtraq_id(56619);
  script_xref(name:"EDB-ID", value:"22902");

  script_name(english:"lighttpd 1.4.31 http_request_split_value Function Header Handling DoS");
  script_summary(english:"Checks version in Server response header.");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of lighttpd running on the remote
host is 1.4.31. It is, therefore, affected by a denial of service
vulnerability. An error in the http_request_split_value() function in
'src/request.c' can cause the application to enter an endless loop
when handling specially crafted 'Connection' header requests.

Note that Nessus has not tested for this issue but has instead relied
only on the version in the server's banner.");
  script_set_attribute(attribute:"see_also", value:"http://www.lighttpd.net/2012/11/21/1-4-32/");
  script_set_attribute(attribute:"see_also", value:"http://redmine.lighttpd.net/issues/2413");
  script_set_attribute(attribute:"see_also", value:"http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2012_01.txt");
  # Patch download
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d138340");
  script_set_attribute(attribute:"solution", value:
"Upgrade to lighttpd version 1.4.32 or later. Alternatively, apply the
vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");


  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lighttpd:lighttpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");

  script_dependencies("lighttpd_detect.nasl");
  script_require_keys("installed_sw/lighttpd", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

appname = "lighttpd";
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80);
app_info = vcf::get_app_info(app:appname, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [{"fixed_version":"1.4.32"}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
