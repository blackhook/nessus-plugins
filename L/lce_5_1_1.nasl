#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118399);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_cve_id("CVE-2018-0732", "CVE-2018-0737");

  script_name(english:"Tenable Log Correlation Engine (LCE) < 5.1.1 (TNS-2018-13)");
  script_summary(english:"Performs a version check.");

  script_set_attribute(attribute:"synopsis", value:
"A data aggregation application installed on the remote host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Tenable Log Correlation Engine (LCE) installed on the
remote host is a version prior to 5.1.1. It is, therefore,
affected by multiple vulnerabilities:

  - A flaw exists in the bundled third-party component OpenSSL
    library's key handling during a TLS handshake that causes a
    denial of service vulnerability due to key handling during a TLS
    handshake. (CVE-2018-0732)

  - A flaw exists in the bundled third-party component OpenSSL
    library's RSA Key generation algorithm that allows a cache timing
    side channel attack to recover the private key. (CVE-2018-0737)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2018-13");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/openssl-1.0.2-notes.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable LCE version 5.1.1 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0737");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:log_correlation_engine");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("lce_installed.nbin");
  script_require_keys("installed_sw/Log Correlation Engine Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

include("vcf.inc");

appname = "Log Correlation Engine Server";
get_install_count(app_name:appname, exit_if_zero:TRUE);
app_info = vcf::get_app_info(app:appname);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "max_version" : "5.1.0", "fixed_version" : "5.1.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
