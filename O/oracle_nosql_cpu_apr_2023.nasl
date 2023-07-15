#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174518);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2022-42003");

  script_name(english:"Oracle NoSQL Database Multiple Vulnerabilities (Apr 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A database running on the remote host is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle NoSQL Database Enterprise running on the remote host is prior to 21.2.63. It is, therefore,
affected by multiple vulnerabilities as referenced in the April 2023 CPU advisory.

  - Vulnerability in Oracle NoSQL Database (component: Administration (jackson-databind)). Easily exploitable
    vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle NoSQL Database.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of Oracle NoSQL Database.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2023.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2023.html#AppendixNSQL");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle NoSQL Database Enterprise version 21.2.63 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42003");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:oracle:nosql_database");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_nosql_nix_installed.nbin");
  script_require_keys("installed_sw/Oracle NoSQL Database");

  exit(0);
}

include('vcf.inc');

var app = vcf::get_app_info(app:'Oracle NoSQL Database');

var constraints =[ {'fixed_version' : '21.2.63'} ];

vcf::check_version_and_report(
  app_info:app,
  constraints:constraints,
  severity:SECURITY_HOLE
);
