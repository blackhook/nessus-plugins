#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(131184);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id(
    "CVE-2015-9251",
    "CVE-2017-3735",
    "CVE-2017-3736",
    "CVE-2017-3738",
    "CVE-2018-0732",
    "CVE-2018-0733",
    "CVE-2018-0737",
    "CVE-2018-0739",
    "CVE-2018-1000120",
    "CVE-2018-1000121",
    "CVE-2018-1000122",
    "CVE-2018-1000300",
    "CVE-2018-1000301"
  );

  script_name(english:"Oracle Enterprise Manager Ops Center (Jan 2019 CPU)");
  script_summary(english:"Checks for the patch ID.");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Cloud Control installed on
the remote host is affected by multiple vulnerabilities in
Enterprise Manager Base Platform component:

  - An unspecified vulnerability in the subcomponent Networking
    (jQuery) of Enterprise Manager Ops Center. Supported versions
    that are affected are 12.2.2 and 12.3.3. An easy to exploit
    vulnerability could allow an unauthenticated attacker with
    network access via HTTP to compromise Enterprise Manager Ops
    Center. A successful attacks requires human interaction and
    can result in unauthorized update, insert or delete access
    to some of Enterprise Manager Ops Center accessible data.
    (CVE-2015-9251)

  - An unspecified vulnerability in the subcomponent Networking
    (OpenSSL) of the Enterprise Manager Ops Center. Supported
    versions that are affected are 12.2.2 and 12.3.3. An easy
    to exploit vulnerability could allow an unauthenticated
    attacker with network access via HTTPS to compromise
    Enterprise Manager Ops Center. A successful attack of this
    vulnerability could result in unauthorized ability to cause
    a hang or frequently repeatable crash (complete DOS) of
    Enterprise Manager Ops Center. (CVE-2018-0732)

  - An unspecified vulnerability in the subcomponent Networking
    (cURL) of Enterprise Manager Ops Center. Supported versions
    that are affected are 12.2.2 and 12.3.3. Difficult to exploit
    vulnerability allows unauthenticated attacker with network
    access via HTTP to compromise Enterprise Manager Ops Center.
    A successful attack requires human interaction from a person
    other than the attacker and can result in takeover of
    Enterprise Manager Ops Center. (CVE-2018-1000300)");
  # https://www.oracle.com/security-alerts/cpujan2019.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69d7e6bf");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2019
Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000300");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/21");

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
  {'min_version': '12.2.2.0', 'max_version': '12.2.2.9999', 'uce_patch': '29215911', 'ui_patch': '29215902'},
  {'min_version': '12.3.3.0', 'max_version': '12.3.3.9999', 'uce_patch': '29215911', 'ui_patch': '29215902'}
];

var app_info = vcf::oracle_em_ops_center::get_app_info();

vcf::oracle_em_ops_center::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
