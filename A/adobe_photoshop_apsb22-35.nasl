##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163028);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2022-34243", "CVE-2022-34244");
  script_xref(name:"IAVA", value:"2022-A-0274-S");

  script_name(english:"Adobe Photoshop 22.x < 22.5.8 / 23.x < 23.4.1 Multiple Vulnerabilities (APSB22-35)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Photoshop installed on remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop installed on the remote Windows host is prior to 22.5.8/23.4.1. It is, therefore,
affected by multiple vulnerabilities as referenced in the apsb22-35 advisory.

  - Adobe Photoshop versions 22.5.7 (and earlier) and 23.3.2 (and earlier) are affected by a Use After Free
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2022-34243)

  - Adobe Photoshop versions 22.5.7 (and earlier) and 23.3.2 (and earlier) are affected by an Access of
    Uninitialized Pointer vulnerability that could lead to disclosure of sensitive memory. An attacker could
    leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2022-34244)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb22-35.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop version 22.5.8/23.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34243");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(416, 824);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_photoshop_installed.nasl");
  script_require_keys("installed_sw/Adobe Photoshop", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Photoshop', win_local:TRUE);

var constraints = [
  { 'min_version' : '22.0.0', 'fixed_version' : '22.5.8' },
  { 'min_version' : '23.0.0', 'fixed_version' : '23.3.3', 'fixed_display' : '23.4.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
