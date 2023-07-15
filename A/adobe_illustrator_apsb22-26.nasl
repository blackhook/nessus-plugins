##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162179);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-30637",
    "CVE-2022-30638",
    "CVE-2022-30639",
    "CVE-2022-30640",
    "CVE-2022-30641",
    "CVE-2022-30642",
    "CVE-2022-30643",
    "CVE-2022-30644",
    "CVE-2022-30645",
    "CVE-2022-30646",
    "CVE-2022-30647",
    "CVE-2022-30648",
    "CVE-2022-30649",
    "CVE-2022-30666",
    "CVE-2022-30667",
    "CVE-2022-30668",
    "CVE-2022-30669"
  );
  script_xref(name:"IAVA", value:"2022-A-0245-S");

  script_name(english:"Adobe Illustrator 25.x < 25.4.6 / 26.x < 26.3.1 Multiple Vulnerabilities (APSB22-26)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Illustrator installed on remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Illustrator installed on the remote Windows host is prior to 26.3.1 or 25.4.6. It is, therefore,
affected by multiple vulnerabilities as referenced in the apsb22-26 advisory.

  - Adobe Illustrator versions 26.0.2 (and earlier) and 25.4.5 (and earlier) are affected by an out-of-bounds
    write vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2022-30649)

  - Adobe Illustrator versions 26.0.2 (and earlier) and 25.4.5 (and earlier) are affected by a Use-After-Free
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2022-30647, CVE-2022-30648)

  - Adobe Illustrator versions 26.0.2 (and earlier) and 25.4.5 (and earlier) are affected by an out-of-bounds
    read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious file. (CVE-2022-30666, CVE-2022-30667, CVE-2022-30668, CVE-2022-30669)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/illustrator/apsb22-26.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Illustrator version 26.3.1 or 25.4.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30649");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 125, 416, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:illustrator");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_illustrator_installed.nasl");
  script_require_keys("SMB/Adobe Illustrator/Installed");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Illustrator', win_local:TRUE);

var constraints = [
  { 'min_version' : '25.0.0', 'max_version' : '25.4.5', 'fixed_version' : '25.4.6' },
  { 'min_version' : '26.0.0', 'max_version' : '26.0.2', 'fixed_version' : '26.3.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
