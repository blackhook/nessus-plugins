#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152035);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2015-0254",
    "CVE-2021-2376",
    "CVE-2021-2378",
    "CVE-2021-2382",
    "CVE-2021-2394",
    "CVE-2021-2397",
    "CVE-2021-2403"
  );
  script_xref(name:"IAVA", value:"2021-A-0326");

  script_name(english:"Oracle WebLogic Server Multiple Vulnerabilities (July 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0, and 14.1.1.0.0 versions of WebLogic Server installed on the remote
host are affected by multiple vulnerabilities as referenced in the July 2021 CPU advisory.

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).
    Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0.
    Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to
    compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of
    Oracle WebLogic Server. (CVE-2021-2394, CVE-2021-2397)

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Security).
    Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0.
    Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to
    compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of
    Oracle WebLogic Server. (CVE-2021-2382)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2394");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_weblogic_server_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Oracle WebLogic Server");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_weblogic::get_app_info();

var constraints = [
  {'min_version' : '14.1.1.0', 'fixed_version' : '14.1.1.0.210701', 'fixed_display' : '33125254 or 33069656'},
  {'min_version' : '12.2.1.4', 'fixed_version' : '12.2.1.4.210629', 'fixed_display' : '33125241 or 33059296'},
  {'min_version' : '12.2.1.3', 'fixed_version' : '12.2.1.3.210630', 'fixed_display' : '33125226 or 33064699'},
  {'min_version' : '12.1.3.0', 'fixed_version' : '12.1.3.0.210720', 'fixed_display' : '32832660'},
  {'min_version' : '10.3.6',   'fixed_version' : '10.3.6.0.210720', 'fixed_display' : '3NVW'}
];

vcf::oracle_weblogic::check_version_and_report(app_info:app_info, severity:SECURITY_HOLE, constraints:constraints);
