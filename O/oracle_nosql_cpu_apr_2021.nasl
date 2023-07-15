#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148977);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-14379",
    "CVE-2020-8908",
    "CVE-2020-11612",
    "CVE-2020-13956",
    "CVE-2020-24553",
    "CVE-2021-21290",
    "CVE-2021-22883",
    "CVE-2021-22884",
    "CVE-2021-23840"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle NoSQL Database Multiple Vulnerabilities (Apr 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A database running on the remote host is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle NoSQL Database Enterprise running on the remote host is prior to 20.3.17. It is, therefore,
affected by multiple vulnerabilities as referenced in the April 2021 CPU advisory.

  - Vulnerability in Oracle NoSQL Database (component: Administration (Node.js)). The supported
    version that is affected is Prior to 20.3. Easily exploitable vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Oracle NoSQL Database.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of Oracle NoSQL Database. (CVE-2021-22883)

  - Security-in-Depth issue in Oracle NoSQL Database (component: Administration (jackson-databind)).
    This vulnerability cannot be exploited in the context of this product. (CVE-2019-14379)

  - Vulnerability in Oracle NoSQL Database (component: Administration (Google Guava)). The supported
    version that is affected is Prior to 20.3. Easily exploitable vulnerability allows low privileged
    attacker with logon to the infrastructure where Oracle NoSQL Database executes to compromise
    Oracle NoSQL Database. Successful attacks of this vulnerability can result in unauthorized read
    access to a subset of Oracle NoSQL Database accessible data. (CVE-2020-8908)
  
  - Vulnerability in Oracle NoSQL Database (component: Administration (Netty)). The supported version
    that is affected is Prior to 20.3. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via HTTP to compromise Oracle NoSQL Database. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash
    (complete DOS) of Oracle NoSQL Database. (CVE-2020-11612)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2021.html#AppendixNSQL");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2021verbose.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2021cvrf.xml");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle NoSQL Database Enterprise version 20.3.17 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14379");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:oracle:nosql_database");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_nosql_nix_installed.nbin");
  script_require_keys("installed_sw/Oracle NoSQL Database");

  exit(0);
}

include('vcf.inc');

var app = vcf::get_app_info(app:'Oracle NoSQL Database');

var constraints =[ {'fixed_version' : '20.3.17'} ];

vcf::check_version_and_report(
  app_info:app,
  constraints:constraints,
  severity:SECURITY_HOLE
);