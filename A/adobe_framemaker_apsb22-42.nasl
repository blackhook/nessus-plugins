##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164018);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2022-34264",
    "CVE-2022-35673",
    "CVE-2022-35674",
    "CVE-2022-35675",
    "CVE-2022-35676",
    "CVE-2022-35677"
  );
  script_xref(name:"IAVB", value:"2022-B-0026-S");

  script_name(english:"Adobe FrameMaker 2019 < 15.0.8 (2019.0.8) / Adobe FrameMaker 2020 < 16.0.4 (2020.0.4) Multiple Vulnerabilities (APSB22-42)");

  script_set_attribute(attribute:"synopsis", value:
"The remote install of Adobe FrameMaker has multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe FrameMaker installed on the remote Windows host is prior to 15.0.8 / 16.0.4. It is, therefore,
affected by multiple vulnerabilities as referenced in the apsb22-42 advisory.

  - Adobe FrameMaker versions 2019 Update 8 (and earlier) and 2020 Update 4 (and earlier) are affected by a
    Heap-based Buffer Overflow vulnerability that could result in arbitrary code execution in the context of
    the current user. Exploitation of this issue requires user interaction in that a victim must open a
    malicious file. (CVE-2022-35676, CVE-2022-35677)

  - Adobe FrameMaker versions 2019 Update 8 (and earlier) and 2020 Update 4 (and earlier) are affected by an
    out-of-bounds read vulnerability that could lead to disclosure of sensitive memory. An attacker could
    leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2022-34264)

  - Adobe FrameMaker versions 2019 Update 8 (and earlier) and 2020 Update 4 (and earlier) are affected by an
    out-of-bounds read vulnerability when parsing a crafted file, which could result in a read past the end of
    an allocated memory structure. An attacker could leverage this vulnerability to execute code in the
    context of the current user. Exploitation of this issue requires user interaction in that a victim must
    open a malicious file. (CVE-2022-35673, CVE-2022-35674)

  - Adobe FrameMaker versions 2019 Update 8 (and earlier) and 2020 Update 4 (and earlier) are affected by a
    Use After Free vulnerability that could result in arbitrary code execution in the context of the current
    user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2022-35675)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/framemaker/apsb22-42.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe FrameMaker version 15.0.8, 16.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-35677");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122, 125, 416);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:framemaker");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_framemaker_installed.nbin");
  script_require_keys("installed_sw/Adobe FrameMaker", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe FrameMaker', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '15.0.8', 'fixed_display' : '15.0.8 / 2019.0.8 / FrameMaker v15.0.8 (2019)' },
  { 'min_version' : '16.0.0', 'fixed_version' : '16.0.4', 'fixed_display' : '16.0.4 / 2020.0.4 / FrameMaker v16.0.4 (2020)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
