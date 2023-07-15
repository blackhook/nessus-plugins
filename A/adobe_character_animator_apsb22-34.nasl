##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163034);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2022-34241", "CVE-2022-34242");
  script_xref(name:"IAVA", value:"2022-A-0275");

  script_name(english:"Adobe Character Animator 4.0.0 < 22.5.0 / 22.0 < 22.5 Multiple Arbitrary code execution (APSB22-34)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Character Animator instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Character Animator installed on the remote Windows host is prior to 22.5, 22.5.0. It is, therefore,
affected by multiple vulnerabilities as referenced in the APSB22-34 advisory.

  - Adobe Character Animator version 4.4.7 (and earlier) and 22.4 (and earlier) are affected by an out-of-
    bounds read vulnerability when parsing a crafted file, which could result in a read past the end of an
    allocated memory structure. An attacker could leverage this vulnerability to execute code in the context
    of the current user. Exploitation of this issue requires user interaction in that a victim must open a
    malicious file. (CVE-2022-34242)

  - Adobe Character Animator version 4.4.7 (and earlier) and 22.4 (and earlier) are affected by a Heap-based
    Buffer Overflow vulnerability that could result in arbitrary code execution in the context of the current
    user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2022-34241)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/character_animator/apsb22-34.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7ecdbab");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Character Animator version 22.5, 22.5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34242");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122, 125);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:character_animator");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_character_animator_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Character Animator");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Character Animator', win_local:TRUE);

var constraints = [
  { 'min_version' : '4.0.0', 'fixed_version' : '22.5.0' },
  { 'min_version' : '22.0', 'fixed_version' : '22.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
