#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135290);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-1927", "CVE-2020-1934");
  script_xref(name:"IAVA", value:"2020-A-0129-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Apache 2.4.x < 2.4.42 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache httpd installed on the remote host is prior to 2.4.42. It is, therefore, affected by multiple
vulnerabilities as referenced in the 2.4.42 advisory.

  - In Apache HTTP Server 2.4.0 to 2.4.41, mod_proxy_ftp may
    use uninitialized memory when proxying to a malicious
    FTP server. (CVE-2020-1934)

  - In Apache HTTP Server 2.4.0 to 2.4.41, redirects
    configured with mod_rewrite that were intended to be
    self-referential might be fooled by encoded newlines and
    redirect instead to an unexpected URL within the
    request URL. (CVE-2020-1927)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.42 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1927");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:httpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl", "apache_http_server_nix_installed.nbin", "apache_httpd_win_installed.nbin");
  script_require_keys("installed_sw/Apache");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::apache_http_server::combined_get_app_info(app:'Apache');

var constraints = [
  { 'min_version' : '2.4.0', 'fixed_version' : '2.4.42', 'modules':['mod_proxy_ftp', 'mod_rewrite'] }
];

vcf::apache_http_server::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
