#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(133091);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2018-11058", "CVE-2019-1547", "CVE-2019-5482");
  script_xref(name:"IAVA", value:"2020-A-0150");
  script_xref(name:"IAVA", value:"2020-A-0481");

  script_name(english:"Oracle Enterprise Manager Ops Center (Jan 2020 CPU)");
  script_summary(english:"Checks for the patch ID.");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Ops Center installed on
the remote host is affected by multiple vulnerabilities in
Enterprise Manager Base Platform component:

  - An unspecified vulnerability in the Networking (Oracle
    Security Service) component of Oracle Enterprise Manager
    Ops Center. An easy to exploit vulnerability could allow
    unauthenticated attacker with network access via HTTPS
    to compromise Enterprise Manager Ops Center.
    A successful attack of this vulnerability can result in
    takeover of Enterprise Manager Ops Center. (CVE-2018-11058)

  - An unspecified vulnerability in the Networking (RSA
      Bsafe) component of Oracle Enterprise Manager Ops Center.
      A difficult to exploit vulnerability could allow a low
      privileged attacker with logon to the infrastructure where
      Enterprise Manager Ops Center executes to compromise
      Enterprise Manager Ops Center. A successful attack of this
      vulnerability can result in takeover of Enterprise Manager
      Ops Center. (CVE-2019-1547)

  - An unspecified vulnerability in the Networking (cURL)
    component of Oracle Enterprise Manager Ops Center.
    Easily exploitable vulnerability allows unauthenticated
    attacker with network access via multiple protocols to
    compromise Enterprise Manager Ops Center. A successful
    attack of this vulnerability can result in takeover of
    Enterprise Manager Ops Center. (CVE-2019-5482)");
  # https://www.oracle.com/security-alerts/cpujan2020.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d22a1e87");
  # https://www.oracle.com/security-alerts/cpujan2020verbose.html#EM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91e1354f");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2020
Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5482");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager_ops_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_ops_center_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Ops Center");

  exit(0);
}

include('vcf_extras_oracle_em_ops_center.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

var constraints = [
  {'min_version': '12.3.3.0', 'max_version': '12.3.3.9999', 'uce_patch': '30670631'},
  {'min_version': '12.4.0.0', 'max_version': '12.4.0.9999', 'uce_patch': '30670627'}
];

var app_info = vcf::oracle_em_ops_center::get_app_info();

vcf::oracle_em_ops_center::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
