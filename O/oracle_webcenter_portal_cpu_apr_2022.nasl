#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159954);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id(
    "CVE-2020-25649",
    "CVE-2021-28657",
    "CVE-2021-29425",
    "CVE-2021-31812",
    "CVE-2021-36090",
    "CVE-2021-37137",
    "CVE-2021-37714",
    "CVE-2021-41165",
    "CVE-2021-44832"
  );
  script_xref(name:"IAVA", value:"2022-A-0171");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle WebCenter Portal Multiple Vulnerabilities (Apr 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebCenter Portal installed on the remote host is missing a security patch from the April 2022
Critical Patch Update (CPU). It is, therefore, affected by multiple vulnerabilities:

  - An XML external entity vulnerability in the bundled jackson-databind component which allows an unauthenticated
    attacker with network access via HTTP to access, create or delete all data accessible to Oracle WebCenter
    Portal. (CVE-2020-25649)

  - Denial of service vulnerabilities in the bundled Apache Tika, jsoup, Netty and Apache Commons Compress components which
    allow an unauthenticated attacker with network access via HTTP to cause a hang or frequently repeatable crash
    of the Oracle WebCenter Portal. (CVE-2020-28657, CVE-2021-36090, CVE-2021-37137, CVE-2021-37714)

  - A path traversal vulnerability in the bundled Apache Commons IO component which allows an unauthenticated attacker
    with network access via HTTP to read, update or delete a subset of data accessible to Oracle WebCenter Portal.
    (CVE-2021-29425)

  - A Denial of service vulnerability in the bundled Apache PDFBox component which allows an unauthenticated attacker
    with logon to the infrastructure where Oracle WebCenter Portal executes, with human interaction from another user
    to cause a hang or frequently repeatable crash of the Oracle WebCenter Portal. (CVE-2021-31912)

  - A cross-site scripting vulnerability in the bundled CKEditor component which allows a low privileged attacker
    with network access via HTTP, with human interaction from another user, to read, update or delete a subset of
    data accessible to Oracle WebCenter Portal. (CVE-2021-41165)

  - A remote code execution vulnerability in the bundled Apache Log4J component which allows a high privileged
    attacker with network access via HTTP to execute arbitrary code on the Oracle WebCenter Portal. (CVE-2021-44832)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44832");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-25649");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:webcenter_portal");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_webcenter_portal_installed.nbin");
  script_require_keys("installed_sw/Oracle WebCenter Portal");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_oracle_webcenter_portal.inc');

var app_info = vcf::oracle_webcenter_portal::get_app_info();

var constraints = [
  { 'min_version' : '12.2.1.3.0', 'fixed_version' : '12.2.1.3.220321' },
  { 'min_version' : '12.2.1.4.0', 'fixed_version' : '12.2.1.4.220314' }
];

vcf::oracle_webcenter_portal::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
