#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153583);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-40438");
  script_xref(name:"IAVA", value:"2021-A-0440-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/15");

  script_name(english:"Apache < 2.4.49 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache httpd installed on the remote host is prior to 2.4.49. It is, therefore, affected by a
vulnerability as referenced in the 2.4.49 changelog.

  - A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the
  remote user. (CVE-2021-40438)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://downloads.apache.org/httpd/CHANGES_2.4");
  script_set_attribute(attribute:"see_also", value:"https://httpd.apache.org/security/vulnerabilities_24.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.49 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40438");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:httpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl", "apache_http_server_nix_installed.nbin", "apache_httpd_win_installed.nbin");
  script_require_keys("installed_sw/Apache");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::apache_http_server::combined_get_app_info(app:'Apache');

var constraints = [
  { 'fixed_version' : '2.4.49', 'modules':['mod_proxy'] }
];

vcf::apache_http_server::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

