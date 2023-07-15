#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109726);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-4994", "CVE-2018-12804", "CVE-2018-12805");
  script_bugtraq_id(104102, 104696, 104697);

  script_name(english:"Adobe <= 9.7.5 Connect Authentication Bypass Vulnerability (APSB18-18, APSB18-22)");
  script_summary(english:"Checks the version of Adobe Connect.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Connect running on the remote host is 9.7.5 or
earlier. It is, therefore, affected by multiple vulnerabilities.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/connect/apsb18-18.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/connect/apsb18-22.html");
  # https://helpx.adobe.com/adobe-connect/kb/update-for-adobe-connect-now-available-includes-latest-security-.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5bd09165");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Connect version 9.8.1 or later, or apply vendor specified mitigation.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12805");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:connect");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_connect_detect.nbin");
  script_require_keys("installed_sw/Adobe Connect");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("http.inc");
include("vcf.inc");

app = "Adobe Connect";
get_install_count(app_name:app, exit_if_zero:TRUE);

# Paranoid since we cannot check for mitigations
if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
      { "max_version" : "9.7.5", "fixed_version" : "9.8.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
