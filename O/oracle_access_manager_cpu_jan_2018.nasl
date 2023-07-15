#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124059);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-2177",
    "CVE-2016-2178",
    "CVE-2016-2180",
    "CVE-2016-2181",
    "CVE-2016-2182",
    "CVE-2016-2183",
    "CVE-2016-6302",
    "CVE-2016-6303",
    "CVE-2016-6304",
    "CVE-2016-6306",
    "CVE-2016-7052",
    "CVE-2016-7055",
    "CVE-2017-3731",
    "CVE-2017-3732",
    "CVE-2017-10262"
  );
  script_bugtraq_id(
    91081,
    91319,
    92117,
    92557,
    92628,
    92630,
    92982,
    92984,
    93150,
    93153,
    93171,
    94242,
    95813,
    95814,
    102562
  );

  script_name(english:"Oracle Access Manager Multiple Vulnerabilities (Jan 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Access Manager installed on the remote
host is 10.1.4.3.x prior to 10.1.4.3.13 or 11.1.2.3.x prior
to 11.1.2.3.180116. It is, therefore, affected by multiple
vulnerabilities as noted in the October 2018 Critical 
Patch Update advisory:

  - A Vulnerability in the Oracle Access Manager component
    of Oracle Fusion Middleware (subcomponent: Web Server
    Plugin (OpenSSL)). The affected version is 10.1.4.3.0. 
    This is a difficult to exploit vulnerability that allows
    unauthenticated attacker with network access via HTTPS
    to compromise Oracle Access Manager. A successful attack
    of this vulnerability may result in unauthorized access
    to critical data or complete access to all Oracle Access
    Manager accessible data. (CVE-2017-3732)

  - A vulnerability in the Oracle Access Manager component
    of Oracle Fusion Middleware (subcomponent: Web Server
    Plugin). The affected version is 11.1.2.3.0. This is a
    difficult to exploit vulnerability that allows an
    unauthenticated attacker with network access via HTTPS
    to compromise Oracle Access Manager. A successful 
    attack of this vulnerability may result in unauthorized
    access to critical data or complete access to all Oracle
    Access Manager accessible data. (CVE-2017-10262)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae82f1b1");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patches according to the January 2018 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6303");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_access_manager_installed.nbin");
  script_require_keys("Oracle/OAM/Installed", "installed_sw/Oracle Access Manager");

  exit(0);
}

include('vcf.inc');
appname = 'Oracle Access Manager';

app_info = vcf::get_app_info(app:appname);

constraints = [
  {'min_version': '10.1.4.3.0', 'fixed_version': '10.1.4.3.13'},
  {'min_version': '11.1.2.3.0', 'fixed_version': '11.1.2.3.180116'}
];

vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_HOLE);