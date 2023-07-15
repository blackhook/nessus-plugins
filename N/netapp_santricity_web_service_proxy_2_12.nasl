#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110943);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-5488");
  script_xref(name:"IAVA", value:"2018-A-0194");

  script_name(english:"NetApp SANtricity Web Services Proxy Unauthenticated RCE");
  script_summary(english:"Checks the version of NetApp SANtricity Web Services Proxy");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running NetApp SANtricity Web Services Proxy that is affected by
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"NetApp SANtricity Web Services Proxy's version number is 01.10.x.x < 02.13.x.x,
prior to version 02.13.x.x.
It is, therefore, affected by a remote code execution vulnerability.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's version number.");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2018-5488");
  script_set_attribute(attribute:"see_also", value:"https://security.netapp.com/advisory/ntap-20180612-0001/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NetApp SANtricity Web Services Proxy version 02.13.x.x or later.
Alternatively, apply the patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5488");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:netapp:webservices");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("netapp_santricity_web_service_proxy_detect.nbin");
  script_require_keys("Settings/ParanoidReport", "installed_sw/NetApp SANtricity Web Services Proxy");
  script_require_ports("Services/www", 8443, 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("vcf.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "NetApp SANtricity Web Services Proxy";
port = get_http_port(default:8080);
app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:4);

constraints = [{"fixed_version":"2.13.x000.0000", "min_version":"1.10.x000.0002", "fixed_display":"2.13.x000.0000"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
