#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(142663);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2020-14570",
    "CVE-2020-14571",
    "CVE-2020-14584",
    "CVE-2020-14585",
    "CVE-2020-14696"
  );
  script_xref(name:"IAVA", value:"2020-A-0327-S");

  script_name(english:"Oracle Business Intelligence Publisher Multiple Vulnerabilities (Jul 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 11.1.1.9.0, 12.2.1.3.0, and 12.2.1.4.0 versions of Oracle Business Intelligence Enterprise Edition
installed on the remote host are affected by multiple vulnerabilities as referenced in the July 2020 CPU advisory.

  - Easily exploitable vulnerability allows unauthenticated 
    attacker with network access via HTTP to compromise Oracle
    BI Publisher. Successful attacks require human interaction
    from a person other than the attacker and while the
    vulnerability is in Oracle BI Publisher, attacks may
    significantly impact additional products. Successful attacks
    of this vulnerability can result in unauthorized access to
    critical data or complete access to all Oracle BI Publisher
    accessible data as well as unauthorized update, insert or
    delete access to some of Oracle BI Publisher accessible data.
    (CVE-2020-14584)

  - Easily exploitable vulnerability allows unauthenticated
    attacker with network access via HTTP to compromise Oracle
    BI Publisher. While the vulnerability is in Oracle BI Publisher,
    attacks may significantly impact additional products. Successful
    attacks of this vulnerability can result in unauthorized update,
    insert or delete access to some of Oracle BI Publisher accessible
    data as well as unauthorized read access to a subset of Oracle BI
    Publisher accessible data. (CVE-2020-14696)

  - Easily exploitable vulnerability allows unauthenticated attacker
    with network access via HTTP to compromise Oracle BI Publisher.
    While the vulnerability is in Oracle BI Publisher, attacks may
    significantly impact additional products. Successful attacks of
    this vulnerability can result in unauthorized update, insert or
    delete access to some of Oracle BI Publisher accessible data as
    well as unauthorized read access to a subset of Oracle BI Publisher
    accessible data. (CVE-2020-14571)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2020 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14696");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14585");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bi_publisher_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Intelligence Publisher");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
app_info = vcf::get_app_info(app:'Oracle Business Intelligence Publisher');

constraints = [
  {'min_version': '11.1.1.9', 'fixed_version': '11.1.1.9.200714', 'patch': '31460938', 'bundle': '31525202'},
  {'min_version': '12.2.1.3', 'fixed_version': '12.2.1.3.200714', 'patch': '31178889', 'bundle': '31178889'},
  {'min_version': '12.2.1.4', 'fixed_version': '12.2.1.4.200714', 'patch': '31178877', 'bundle': '31178877'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_WARNING);

