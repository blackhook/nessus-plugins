##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146447);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id(
    "CVE-2021-21047",
    "CVE-2021-21048",
    "CVE-2021-21049",
    "CVE-2021-21050",
    "CVE-2021-21051"
  );
  script_xref(name:"IAVA", value:"2021-A-0076-S");

  script_name(english:"Adobe Photoshop 21.x < 21.2.5 / 22.x < 22.2 Multiple Vulnerabilities (macOS APSB21-10)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Photoshop installed on remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop installed on the remote macOS or Mac OS X host is prior to 21.2.5/22.2. It is, therefore,
affected by multiple vulnerabilities as referenced in the apsb21-10 advisory.

  - Adobe Photoshop versions 21.2.4 (and earlier) and 22.1.1 (and earlier) are affected by an Out-of-bounds
    Write vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary
    code execution in the context of the current user. Exploitation of this issue requires user interaction in
    that a victim must open a malicious file. (CVE-2021-21047)

  - Adobe Photoshop versions 21.2.4 (and earlier) and 22.1.1 (and earlier) are affected by a Memory Corruption
    vulnerability when parsing a specially crafted file. An unauthenticated attacker could leverage this
    vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file (CVE-2021-21048)

  - Adobe Photoshop versions 21.2.4 (and earlier) and 22.1.1 (and earlier) are affected by an Out-of-bounds
    Read vulnerability when parsing a specially crafted file. An unauthenticated attacker could leverage this
    vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2021-21049,
    CVE-2021-21050)

  - Adobe Photoshop versions 21.2.4 (and earlier) and 22.1.1 (and earlier) are affected by a Buffer Overflow
    vulnerability when parsing a specially crafted javascript file. An unauthenticated attacker could leverage
    this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of
    this issue requires user interaction in that a victim must open a malicious file. (CVE-2021-21051)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb21-10.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop version 21.2.5/22.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21051");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_photoshop_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Photoshop");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit('Host/MacOSX/Version');

app_info = vcf::get_app_info(app:'Adobe Photoshop');

constraints = [
  { 'min_version' : '21.0.0', 'max_version' : '21.2.4', 'fixed_version' : '21.2.5' },
  { 'min_version' : '22.0.0', 'max_version' : '22.1.1', 'fixed_version' : '22.2.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
