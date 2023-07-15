#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133045);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-3736", "CVE-2018-2585");
  script_bugtraq_id(101666, 102674);

  script_name(english:"Oracle MySQL Connectors Multiple Vulnerabilities (Jan 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle MySQL Connectors installed on the remote host is Connector/NET 6.9.x prior to 6.9.11 or 6.10.x
prior to 6.10.6, or Connector/ODBC 5.3.x prior to 5.3.10. It is, therefore, affected by multiple vulnerabilities as
noted in the January 2018 Critical Patch Update advisory:

  - An unspecified vulnerability in Connector/NET subcomponent. An unauthenticated, remote attacker can
    exploit this issue to cause a denial of service (DoS) condition. (CVE-2018-2585)

  - A vulnerability in the Connector/ODBC subcomponent's OpenSSL version due to a carry propagating bug in the
    x86_64 Montgomery squaring procedure. An authenticated, remote attacker with a large amount of resources
    may be able to exploit this to compromise confidentiality. (CVE-2017-3736)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2018.html");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2336646.1");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patches according to the January 2018 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3736");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_connectors");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_connectors_version_nix.nbin", "mysql_connectors_version_win.nbin");
  script_require_keys("installed_sw/MySQL Connector");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'MySQL Connector');
product = tolower(app_info['Product']);

vcf::check_granularity(app_info:app_info, sig_segments:3);

if ('odbc' >< product)
  constraints = [
    {'min_version': '5.3.0', 'fixed_version': '5.3.10'}
  ];
else if ('net' >< product)
  constraints = [
    {'min_version': '6.9.0', 'fixed_version': '6.9.11'},
    {'min_version': '6.10.0', 'fixed_version': '6.10.6'},
  ];
else
  audit(AUDIT_PACKAGE_NOT_AFFECTED, product);

vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_WARNING);
