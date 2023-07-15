#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157448);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/20");

  script_cve_id(
    "CVE-2022-23186",
    "CVE-2022-23188",
    "CVE-2022-23189",
    "CVE-2022-23190",
    "CVE-2022-23191",
    "CVE-2022-23192",
    "CVE-2022-23193",
    "CVE-2022-23194",
    "CVE-2022-23195",
    "CVE-2022-23196",
    "CVE-2022-23197",
    "CVE-2022-23198",
    "CVE-2022-23199"
  );
  script_xref(name:"IAVA", value:"2022-A-0070-S");

  script_name(english:"Adobe Illustrator 26.x < 26.0.3 / 25.x < 25.4.4 Multiple Vulnerabilities (APSB22-07)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Illustrator installed on remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Illustrator installed on the remote Windows host is prior to 26.0.3 or 25.4.4. It is, therefore,
affected by multiple vulnerabilities as referenced in the apsb22-07 advisory.

  - Adobe Illustrator versions 25.4.3 (and earlier) and 26.0.2 (and earlier) are affected by a Null pointer
    dereference vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve an
    application denial-of-service in the context of the current user. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2022-23189, CVE-2022-23198, CVE-2022-23199)

  - Adobe Illustrator versions 25.4.3 (and earlier) and 26.0.2 (and earlier) are affected by an out-of-bounds
    write vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2022-23186)

  - Adobe Illustrator versions 25.4.3 (and earlier) and 26.0.2 (and earlier) are affected by a buffer overflow
    vulnerability due to insecure handling of a crafted malicious file, potentially resulting in arbitrary
    code execution in the context of the current user. Exploitation requires user interaction in that a victim
    must open a crafted malicious file in Illustrator. (CVE-2022-23188)

  - Adobe Illustrator versions 25.4.3 (and earlier) and 26.0.2 (and earlier) are affected by an out-of-bounds
    read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious file. (CVE-2022-23190, CVE-2022-23191, CVE-2022-23192, CVE-2022-23193,
    CVE-2022-23194, CVE-2022-23195, CVE-2022-23196, CVE-2022-23197)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/120.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/125.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/476.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/787.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/788.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/illustrator/apsb22-07.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Illustrator version 26.0.3 or 25.4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23188");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(120, 125, 476, 787, 788);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:illustrator");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_illustrator_installed.nasl");
  script_require_keys("SMB/Adobe Illustrator/Installed");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Illustrator', win_local:TRUE);

var constraints = [
  { 'min_version' : '25.0.0', 'max_version' : '25.4.3', 'fixed_version' : '25.4.4' },
  { 'min_version' : '26.0.0', 'max_version' : '26.0.2', 'fixed_version' : '26.0.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
