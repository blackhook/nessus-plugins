#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152034);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id("CVE-2019-11358", "CVE-2021-2457", "CVE-2021-2458");
  script_xref(name:"IAVA", value:"2021-A-0326");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Identity Manager (Jul 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 11.1.2.2.0, 11.1.2.3.0, 12.2.1.3.0, and 12.2.1.4.0 versions of Identity Manager installed on the remote host are
affected by multiple vulnerabilities as referenced in the July 2021 CPU advisory.

  - Vulnerability in the Identity Manager product of Oracle Fusion Middleware (component: Identity Console).
    Supported versions that are affected are 11.1.2.2.0, 11.1.2.3.0, 12.2.1.3.0 and 12.2.1.4.0. Easily
    exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise
    Identity Manager. Successful attacks require human interaction from a person other than the attacker and
    while the vulnerability is in Identity Manager, attacks may significantly impact additional products.
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete
    access to all Identity Manager accessible data as well as unauthorized update, insert or delete access to
    some of Identity Manager accessible data. (CVE-2021-2458)

  - Vulnerability in the Identity Manager product of Oracle Fusion Middleware (component: UI Platform
    (jQuery)). The supported version that is affected is 12.2.1.3.0. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Identity Manager. Successful attacks
    require human interaction from a person other than the attacker and while the vulnerability is in Identity
    Manager, attacks may significantly impact additional products. Successful attacks of this vulnerability
    can result in unauthorized update, insert or delete access to some of Identity Manager accessible data as
    well as unauthorized read access to a subset of Identity Manager accessible data. (CVE-2019-11358)

  - Vulnerability in the Identity Manager product of Oracle Fusion Middleware (component: Request Management &
    Workflow). The supported version that is affected is 11.1.2.3.0. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Identity Manager. Successful attacks
    of this vulnerability can result in unauthorized read access to a subset of Identity Manager accessible
    data. (CVE-2021-2457)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2457");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-2458");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:identity_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_identity_management_installed.nbin");
  script_require_keys("installed_sw/Oracle Identity Manager");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Identity Manager');

var constraints = [
  { 'min_version' : '11.1.2.3.0', 'fixed_version' : '11.1.2.3.210713' },
  { 'min_version' : '12.2.1.3.0', 'fixed_version' : '12.2.1.3.210713' },
  { 'min_version' : '12.2.1.4.0', 'fixed_version' : '12.2.1.4.210708' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);