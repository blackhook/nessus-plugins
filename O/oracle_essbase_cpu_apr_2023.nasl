#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174567);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2023-0215",
    "CVE-2023-21942",
    "CVE-2023-21943",
    "CVE-2023-21944",
    "CVE-2022-39135",
    "CVE-2022-46364",
    "CVE-2023-23914",
    "CVE-2023-23915",
    "CVE-2023-23916"
  );
  script_xref(name:"IAVA", value:"2023-A-0206");

  script_name(english:"Oracle Essbase (April 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A business analytics solution installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Essbase installed on the remote host is missing a security patch from the April 2023
Critical Patch Update (CPU). It is, therefore, affected by multiple vulnerabilities, including following that are remotely exploitable:

  - Vulnerability in Security and Provisioning component of Oracle Essbase version 21.4. The public API function BIO_new_NDEF is
    a helper function used for streaming ASN.1 data via a BIO. Under certain conditions, the BIO chain is not properly cleaned up
    and the BIO passed by the caller still retains internal pointers to the previously freed filter BIO. This will most likely 
    result in a crash. (CVE-2023-0215)

  - Vulnerability in Security and Provisioning component of Oracle Essbase version 21.4. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Oracle Essbase. Successful attacks require human interaction
    from a person other than the attacker. Successful attacks of this vulnerability can result in unauthorized access to critical 
    data or complete access to all Oracle Essbase accessible data. (CVE-2023-21942, CVE-2023-21943, CVE-2023-21944)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-46364");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:essbase");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_essbase_installed.nbin");
  script_require_keys("installed_sw/Oracle Essbase");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Essbase');

var constraints = [
  { 'min_version' : '21.4.0.0', 'fixed_version' : '21.4.3.0', 'fixed_display' : '21.4.3.0 (Patch 34966497)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
