#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158729);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/15");

  script_cve_id("CVE-2022-24090");
  script_xref(name:"IAVA", value:"2022-A-0113-S");

  script_name(english:"Adobe Photoshop 22.x < 22.5.6 / 23.x < 23.2 Vulnerability (macOS APSB22-14)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Photoshop installed on remote macOS or Mac OS X host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop installed on the remote macOS or Mac OS X host is prior to 22.5.6/23.2. It is, therefore,
affected by a vulnerability as referenced in the apsb22-14 advisory.

  - Adobe Photoshop versions 23.1.1 (and earlier) and 22.5.5 (and earlier) are affected by an out-of-bounds
    read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious file. (CVE-2022-24090)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/788.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb22-14.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop version 22.5.6/23.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24090");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(788);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_photoshop_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Photoshop");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit('Host/MacOSX/Version');

var app_info = vcf::get_app_info(app:'Adobe Photoshop');

var constraints = [
  { 'min_version' : '22.0.0', 'fixed_version' : '22.5.6' },
  { 'min_version' : '23.0.0', 'fixed_version' : '23.1.2', 'fixed_display' : '23.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
