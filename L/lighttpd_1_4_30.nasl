#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57410);
  script_version("1.13");
  script_cvs_date("Date: 2018/11/15 20:50:25");

  script_cve_id("CVE-2011-4362");
  script_bugtraq_id(50851);
  script_xref(name:"EDB-ID", value:"18295");

  script_name(english:"lighttpd < 1.4.30 base64_decode Function Out-of-Bounds Read Error DoS");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of lighttpd running on the remote
host is prior to 1.4.30. It is, therefore, affected by a denial of
service vulnerability. The HTTP server allows out-of-bounds values to
be decoded during the auth process and later uses these values as
offsets. Using negative values as offsets can result in application
crashes.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cdaac48a");
  script_set_attribute(attribute:"see_also", value:"http://redmine.lighttpd.net/issues/2370");
  script_set_attribute(attribute:"see_also", value:"http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2011_01.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to lighttpd version 1.4.30 or later. Alternatively, apply the
vendor-supplied patch or disable mod_auth.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lighttpd:lighttpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/lighttpd", "Settings/ParanoidReport");
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

constraints = [{"fixed_version":"1.4.30"}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
