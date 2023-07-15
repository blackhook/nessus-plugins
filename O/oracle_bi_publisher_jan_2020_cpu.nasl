#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132991);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-1559",
    "CVE-2020-2531",
    "CVE-2020-2535",
    "CVE-2020-2537"
  );
  script_bugtraq_id(107174);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Business Intelligence Publisher Multiple Vulnerabilities (Jan 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Intelligence Publisher running on the
remote host is 11.1.1.9.x prior to 11.1.1.9.200114 or 12.2.1.3.x 
prior to 12.2.1.3.200114 or 12.2.1.4.x prior to 12.2.1.4.200114. 
It is, therefore, affected by  multiple vulnerabilities as noted in
the January 2020 Critical Patch Update advisory:

  - An unspecified vulnerability in the Analytics Server
    and Analytics Web General (OpenSSL)) component of Oracle BI
    Publisher. The vulnerability could allow an
    unauthenticated attacker with network access via HTTPS
    to compromise Oracle BI Publisher. A successful attack
    could result in unauthorized access to critical data
    or complete access to all Oracle Business Intelligence
    Enterprise Edition accessible data. (CVE-2019-1559)
    
  - An unspecified vulnerability in the BI Platform Security)
    component of Oracle BI Publisher. The vulnerability could
    allow an unauthenticated attacker with network access via
    HTTPS to compromise Oracle BI Publisher. A successful
    attack would require human interaction from a person other
    than the attacker resulting in unauthorized read access to
    a subset of Oracle BI Publisher accessible data.
    (CVE-2020-2531)

  - An unspecified vulnerability in the Analytics Server)
    component of Oracle BI Publisher. An easy to exploit
    vulnerability could allow an unauthenticated attacker with
    network access via HTTP to compromise Oracle BI Publisher.
    A successful attack would require human interaction from a
    person other than the attacker resulting in unauthorized
    read access to a subset of Oracle BI Publisher accessible
    data.(CVE-2020-2535)

  - An unspecified vulnerability in the Analytics Actions)
    component of Oracle BI Publisher. An easy to exploit
    vulnerability could allow an unauthenticated attacker with
    network access via HTTP to compromise Oracle BI Publisher.
    A successful attack would require human interaction from a
    person other than the attacker resulting in unauthorized
    read access to a subset of Oracle BI Publisher accessible
    data and unauthorized ability to cause a partial denial of
    service (partial DOS) of Oracle Business Intelligence
    Enterprise Edition. (CVE-2020-2537)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/security-alerts/cpujan2020.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d22a1e87");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2020 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2537");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
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
  {'min_version': '11.1.1.9', 'fixed_version': '11.1.1.9.200114', 'patch': '30406851', 'bundle': '30677050'},
  {'min_version': '12.2.1.3', 'fixed_version': '12.2.1.3.200114', 'patch': '30499022', 'bundle': '30499022'},
  {'min_version': '12.2.1.4', 'fixed_version': '12.2.1.4.200114', 'patch': '30499026', 'bundle': '30499026'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_WARNING);

