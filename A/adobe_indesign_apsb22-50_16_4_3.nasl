#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165355);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-28852",
    "CVE-2022-28853",
    "CVE-2022-28854",
    "CVE-2022-28855",
    "CVE-2022-28856",
    "CVE-2022-28857",
    "CVE-2022-30671",
    "CVE-2022-30672",
    "CVE-2022-30673",
    "CVE-2022-30674",
    "CVE-2022-30675",
    "CVE-2022-30676",
    "CVE-2022-38413",
    "CVE-2022-38414",
    "CVE-2022-38415",
    "CVE-2022-38416",
    "CVE-2022-38417"
  );

  script_name(english:"Adobe InDesign 16.x < 16.4.3 / 17.x  < 17.4 Multiple Vulnerabilities (APSB22-50)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote host is prior to 16.4.3. It is, therefore, affected by
multiple vulnerabilities, as follows:

  - An out-of-bounds write vulnerability allows arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2022-28852, CVE-2022-28853)

  - A Heap-based Buffer Overflow vulnerability could result in arbitrary code execution in the context of the current
    user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2022-38413, CVE-2022-38414, CVE-2022-38415)
    
  - An an out-of-bounds read vulnerability exists when parsing a crafted file, which could result in a read past the
    end of an allocated memory structure. An attacker could leverage this vulnerability to execute code in the context
    of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious
    file. (CVE-2022-38416, CVE-2022-38417)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/indesign/apsb22-50.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InDesign version 16.4.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38417");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_indesign_installed.nbin", "macosx_adobe_indesign_installed.nbin");
  script_require_keys("installed_sw/Adobe InDesign");

  exit(0);
}

include('vcf.inc');

var win_local = FALSE;

if (!empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
  win_local = TRUE;

var app_info = vcf::get_app_info(app:'Adobe InDesign', win_local:win_local);

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '16.4.3' },
  { 'min_version' : '17.0', 'fixed_version' : '17.4' },
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
