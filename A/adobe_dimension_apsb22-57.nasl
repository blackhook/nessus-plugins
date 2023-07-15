#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166130);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-38440",
    "CVE-2022-38441",
    "CVE-2022-38442",
    "CVE-2022-38443",
    "CVE-2022-38444",
    "CVE-2022-38445",
    "CVE-2022-38446",
    "CVE-2022-38447",
    "CVE-2022-38448"
  );
  script_xref(name:"IAVA", value:"2022-A-0417-S");

  script_name(english:"Adobe Dimension < 3.4.6 Multiple Vulnerabilities (APSB22-57)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Dimension installed on the remote host is prior to 3.4.6. It is, therefore, affected by multiple
vulnerabilities, including the following:

  - Two arbitrary code execution vulnerabilities caused by out-of-bounds reads. An unauthenticated, local
    attacker can exploit these to execute code. (CVE-2022-38440, CVE-2022-38441)

  - Multiple arbitrary code execution vulnerabilities caused by a use-after-free flaws. An unauthenticated,
    local attacker can exploit these to execute code. (CVE-2022-38442, CVE-2022-38444, CVE-2022-38445,
    CVE-2022-38446, CVE-2022-38447, CVE-2022-38448)

  - A memory leak vulnerability caused by an out-of-bound read. An unauthenticated, local attacker can
    exploit this to compromise confidentiality. (CVE-2022-38443)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/dimension/apsb22-57.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Dimension version 3.4.6 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38448");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:dimension");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_dimension_installed.nbin", "macos_adobe_dimension_installed.nbin");
  script_require_keys("installed_sw/Adobe Dimension");

  exit(0);
}

include('vcf.inc');

var win_local = FALSE;

if (get_kb_item('SMB/Registry/Enumerated'))
  win_local = TRUE;

var app_info = vcf::get_app_info(app:'Adobe Dimension', win_local:win_local);

var constraints = [
  { 'fixed_version' : '3.4.6'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
