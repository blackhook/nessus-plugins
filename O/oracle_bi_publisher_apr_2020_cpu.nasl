#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135678);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2015-7940", "CVE-2016-1000031", "CVE-2020-2950");
  script_bugtraq_id(79091, 93604);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Business Intelligence Publisher Multiple Vulnerabilities (Apr 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Intelligence Publisher running on the
remote host is 11.1.1.9.x prior to 11.1.1.9.200414 or 12.2.1.3.x 
prior to 12.2.1.3.200414 or 12.2.1.4.x prior to 12.2.1.4.200414. 
It is, therefore, affected by multiple vulnerabilities as noted in
the April 2020 Critical Patch Update advisory

  - An unspecified vulnerability in the Analystics Web
    General component of Oracle BI Published. An easily
    exploitable vulnerability could allow an
    unauthenticated attacker with network access via HTTP
    to compromise Oracle Business Intelligence Enterprise
    Edition. A successful attacks of this vulnerability
    can result in takeover of Oracle Business Intelligence
    Enterprise Edition. (CVE-2020-2950)

  - The Bouncy Castle Java library before 1.51 does not
    validate a point is withing the elliptic curve, which
    makes it easier for remote attackers to obtain private
    keys via a series of crafted elliptic curve Diffie
    Hellman (ECDH) key exchanges, aka an invalid curve
    attack. (CVE-2015-7940)

  - Apache Commons FileUpload before 1.3.3 DiskFileItem File
    Manipulation Remote Code Execution (CVE-2016-1000031)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2020 Oracle Critical Patch Update
advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2950");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

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
  {'min_version': '11.1.1.9', 'fixed_version': '11.1.1.9.200414', 'patch': '30992893', 'bundle': '31094216'},
  {'min_version': '12.2.1.3', 'fixed_version': '12.2.1.3.200414', 'patch': '30768584', 'bundle': '30768584'},
  {'min_version': '12.2.1.4', 'fixed_version': '12.2.1.4.200414', 'patch': '30768593', 'bundle': '30768593'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_HOLE);
