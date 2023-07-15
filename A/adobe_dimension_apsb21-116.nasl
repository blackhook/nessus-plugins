##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161867);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/18");

  script_cve_id(
    "CVE-2021-43763",
    "CVE-2021-44179",
    "CVE-2021-44180",
    "CVE-2021-44181",
    "CVE-2021-44182",
    "CVE-2021-44183"
  );
  script_xref(name:"IAVA", value:"2021-A-0595-S");

  script_name(english:"Adobe Dimension < 3.4.4 Multiple Vulnerabilities (APSB21-116)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Dimension installed on the remote host is prior to 3.4.4. It is, therefore, affected by multiple
vulnerabilities, including the following:

  - Adobe Dimension versions 3.4.3 (and earlier) is affected by a memory corruption vulnerability due to
    insecure handling of a malicious GIF file, potentially resulting in arbitrary code execution in the
    context of the current user. User interaction is required to exploit this vulnerability. (CVE-2021-44179)

  - Adobe Dimension versions 3.4.3 (and earlier) are affected by an out-of-bounds write vulnerability that
    could result in arbitrary code execution in the context of the current user. Exploitation of this issue
    requires user interaction in that a victim must open a malicious GIF file. (CVE-2021-44180)

  - Adobe Dimension versions 3.4.3 (and earlier) are affected by an out-of-bounds write vulnerability that
    could result in arbitrary code execution in the context of the current user. Exploitation of this issue
    requires user interaction in that a victim must open a malicious GIF file. (CVE-2021-44181)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/dimension/apsb21-116.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Dimension version 3.4.4 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44181");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:dimension");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'fixed_version' : '3.4.4'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
