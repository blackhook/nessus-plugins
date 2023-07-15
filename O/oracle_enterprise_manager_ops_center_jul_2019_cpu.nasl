#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(126777);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2019-0196",
    "CVE-2019-0197",
    "CVE-2019-0211",
    "CVE-2019-0215",
    "CVE-2019-0217",
    "CVE-2019-0220",
    "CVE-2019-1559",
    "CVE-2019-2728",
    "CVE-2019-3822"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2019-0203");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2019-0227");

  script_name(english:"Oracle Enterprise Manager Ops Center (Jul 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Cloud Control installed on
the remote host is affected by multiple vulnerabilities in
Enterprise Manager Base Platform component:

  - An unspecified vulnerability in Networking (cURL) subcomponent
    of Oracle Enterprise Manager Ops Center, which could allow
    an unauthenticated attacker with network access to
    compromise Enterprise Manager Ops Center. (CVE-2019-3822)

  - An unspecified vulnerability in Networking (OpenSSL) subcomponent
    of Oracle Enterprise Manager Ops Center, which could allow
    an unauthenticated attacker with network access to
    compromise Enterprise Manager Ops Center. (CVE-2019-1559)

  - An unspecified vulnerability in Networking (OpenSSL) subcomponent
    of Oracle Enterprise Manager Ops Center, which could allow
    a low privileged attacker with network access to
    compromise Enterprise Manager Ops Center. (CVE-2019-2728)");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9aa2b901");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2019
Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3822");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager_ops_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_ops_center_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Ops Center");

  exit(0);
}

include('vcf_extras_oracle_em_ops_center.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

var constraints = [
  {'min_version': '12.3.3.0', 'max_version': '12.3.3.9999', 'uce_patch': '29943334'},
  {'min_version': '12.4.0.0', 'max_version': '12.4.0.9999', 'uce_patch': '30044132'}
];

var app_info = vcf::oracle_em_ops_center::get_app_info();

vcf::oracle_em_ops_center::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
