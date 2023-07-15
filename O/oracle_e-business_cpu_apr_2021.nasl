#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148952);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id(
    "CVE-2017-14735",
    "CVE-2019-10086",
    "CVE-2020-1967",
    "CVE-2020-9488",
    "CVE-2021-2150",
    "CVE-2021-2153",
    "CVE-2021-2155",
    "CVE-2021-2156",
    "CVE-2021-2181",
    "CVE-2021-2182",
    "CVE-2021-2183",
    "CVE-2021-2184",
    "CVE-2021-2185",
    "CVE-2021-2186",
    "CVE-2021-2187",
    "CVE-2021-2188",
    "CVE-2021-2189",
    "CVE-2021-2190",
    "CVE-2021-2195",
    "CVE-2021-2197",
    "CVE-2021-2198",
    "CVE-2021-2199",
    "CVE-2021-2200",
    "CVE-2021-2205",
    "CVE-2021-2206",
    "CVE-2021-2209",
    "CVE-2021-2210",
    "CVE-2021-2222",
    "CVE-2021-2223",
    "CVE-2021-2224",
    "CVE-2021-2225",
    "CVE-2021-2227",
    "CVE-2021-2228",
    "CVE-2021-2229",
    "CVE-2021-2231",
    "CVE-2021-2233",
    "CVE-2021-2235",
    "CVE-2021-2236",
    "CVE-2021-2237",
    "CVE-2021-2238",
    "CVE-2021-2239",
    "CVE-2021-2241",
    "CVE-2021-2246",
    "CVE-2021-2247",
    "CVE-2021-2249",
    "CVE-2021-2251",
    "CVE-2021-2252",
    "CVE-2021-2254",
    "CVE-2021-2255",
    "CVE-2021-2258",
    "CVE-2021-2259",
    "CVE-2021-2260",
    "CVE-2021-2261",
    "CVE-2021-2262",
    "CVE-2021-2263",
    "CVE-2021-2267",
    "CVE-2021-2268",
    "CVE-2021-2269",
    "CVE-2021-2270",
    "CVE-2021-2271",
    "CVE-2021-2272",
    "CVE-2021-2273",
    "CVE-2021-2274",
    "CVE-2021-2275",
    "CVE-2021-2276",
    "CVE-2021-2288",
    "CVE-2021-2289",
    "CVE-2021-2290",
    "CVE-2021-2292",
    "CVE-2021-2295",
    "CVE-2021-2314",
    "CVE-2021-2316"
  );
  script_bugtraq_id(105656);
  script_xref(name:"IAVA", value:"2021-A-0199-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle E-Business Suite Multiple Vulnerabilities (April 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business Suite installed on the remote host is affected by multiple vulnerabilities as
referenced in the April 2021 CPU advisory.

  - A vulnerability exists in the Oracle Applications Framework product of Oracle E-Business Suite (component:
    Home page). The supported version that is affected is 12.2.10. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Oracle Applications Framework.
    Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification
    access to critical data or all Oracle Applications Framework accessible data as well as unauthorized
    access to critical data or complete access to all Oracle Applications Framework accessible data.
    (CVE-2021-2200)

  - A vulnerability exists in the Oracle Marketing product of Oracle E-Business Suite (component: Marketing
    Administration). Supported versions that are affected are 12.2.7-12.2.10. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Oracle Marketing. Successful
    attacks of this vulnerability can result in unauthorized creation, deletion or modification access to
    critical data or all Oracle Marketing accessible data as well as unauthorized access to critical data or 
    complete access to all Oracle Marketing accessible data. (CVE-2021-2205)

  - A vulnerability exists in the Oracle Email Center product of Oracle E-Business Suite (component: Message
    Display). Supported versions that are affected are 12.1.1-12.1.3 and 12.2.3-12.2.10. Easily exploitable
    vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Email
    Center. While the vulnerability is in Oracle Email Center, attacks may significantly impact additional
    products. Successful attacks of this vulnerability can result in unauthorized access to critical data or
    complete access to all Oracle Email Center accessible data as well as unauthorized update, insert or
    delete access to some of Oracle Email Center accessible data. (CVE-2021-2209)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10086");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-2205");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_ebusiness::get_app_info();

var constraints = [
  { 'min_version' : '12.1.1', 'max_version' : '12.1.3',  'fix_patches' : '32438190' },
  { 'min_version' : '12.2.0', 'max_version' : '12.2.2',  'fix_patches' : '32438203', 'fixed_display' : '12.2.3' },
  { 'min_version' : '12.2.3', 'max_version' : '12.2.10', 'fix_patches' : '32438203' }
];

var fix_date = '202104';

vcf::oracle_ebusiness::check_version_and_report(
  app_info    : app_info,
  severity    : SECURITY_HOLE,
  constraints : constraints,
  fix_date    : fix_date
);
