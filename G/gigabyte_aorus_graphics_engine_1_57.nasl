#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169902);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id(
    "CVE-2018-19320",
    "CVE-2018-19321",
    "CVE-2018-19322",
    "CVE-2018-19323"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/11/14");

  script_name(english:"GIGABYTE AORUS GRAPHICS ENGINE < 1.57 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The GIGABYTE AORUS GRAPHICS ENGINE software installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of GIGABYTE AORUS GRAPHICS ENGINE installed on the remote host is prior to 1.57. It is, therefore, affected
by multiple vulnerabilities as referenced in GIGABYTE security advisory 1801:

    - The GDrv low-level driver in GIGABYTE APP Center v1.05.21 and earlier, AORUS GRAPHICS ENGINE before 1.57, XTREME
      GAMING ENGINE before 1.26, and OC GURU II v2.08 exposes ring0 memcpy-like functionality that could allow a local
      attacker to take complete control of the affected system. (CVE-2018-19320)

    - The GPCIDrv and GDrv low-level drivers in GIGABYTE APP Center v1.05.21 and earlier, AORUS GRAPHICS ENGINE before
      1.57, XTREME GAMING ENGINE before 1.26, and OC GURU II v2.08 expose functionality to read and write arbitrary
      physical memory. This could be leveraged by a local attacker to elevate privileges. (CVE-2018-19321)

    - The GPCIDrv and GDrv low-level drivers in GIGABYTE APP Center v1.05.21 and earlier, AORUS GRAPHICS ENGINE before
      1.57, XTREME GAMING ENGINE before 1.26, and OC GURU II v2.08 expose functionality to read/write data from/to IO
      ports. This could be leveraged in a number of ways to ultimately run code with elevated privileges.
      (CVE-2018-19322)

    - The GDrv low-level driver in GIGABYTE APP Center v1.05.21 and earlier, AORUS GRAPHICS ENGINE before 1.57, XTREME
      GAMING ENGINE before 1.26, and OC GURU II v2.08 exposes functionality to read and write Machine Specific Registers
      (MSRs). (CVE-2018-19323)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.secureauth.com/labs/advisories/gigabyte-drivers-elevation-of-privilege-vulnerabilities/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?112be763");
  script_set_attribute(attribute:"see_also", value:"https://www.gigabyte.com/Support/Security/1801");
  script_set_attribute(attribute:"solution", value:
"Upgrade to GIGABYTE AORUS GRAPHICS ENGINE 1.57 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19323");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gigabyte:aorus_graphics_engine");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("gigabyte_aorus_graphics_engine_win_installed.nbin");
  script_require_keys("installed_sw/GIGABYTE APP CENTER");

  exit(0);
}

include('vcf.inc');

var app = 'GIGABYTE AORUS GRAPHICS ENGINE';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'fixed_version':'1.57' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
