#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154253);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/21");

  script_cve_id(
    "CVE-2021-21290",
    "CVE-2021-21295",
    "CVE-2021-21409",
    "CVE-2021-30129",
    "CVE-2021-34558",
    "CVE-2021-37136",
    "CVE-2021-37137"  
  );

  script_name(english:"Oracle NoSQL Database Multiple Vulnerabilities (Oct 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A database running on the remote host is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle NoSQL Database Enterprise running on the remote host is prior to 21.1.12. It is, therefore,
affected by multiple vulnerabilities as referenced in the October 2021 CPU advisory.

  - Security-in-Depth issue in Oracle NoSQL Database (component: Administration (Netty). This vulnerability 
    cannot be exploited in the context of this product. (CVE-2021-21409)

  - Security-in-Depth issue in Oracle NoSQL Database (component: Snappy frame decoder function). The Snappy
    frame decoder function doesn't restrict the chunk length which may lead to excessive memory usage. Beside
    this it also may buffer reserved skippable chunks until the whole chunk was received which may lead to
    excessive memory usage as well. This vulnerability can be triggered by supplying malicious input that
    decompresses to a very big size (via a network stream or a file) or by sending a huge skippable chunk.
    (CVE-2021-37137)

  - Security-in-Depth issue in Oracle NoSQL Database (component: Administration (Go). This vulnerability 
    cannot be exploited in the context of this product. (CVE-2021-34558)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2022.html#AppendixNSQL");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2022verbose.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2022.html#AppendixNSQL");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2022verbose.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2021.html#AppendixNSQL");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2021verbose.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2021cvrf.xml");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle NoSQL Database Enterprise version 21.1.12 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/20");

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

var constraints =[ {'fixed_version' : '21.1.12'} ];

vcf::check_version_and_report(
  app_info:app,
  constraints:constraints,
  severity:SECURITY_NOTE
);
