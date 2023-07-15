#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154436);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/20");

  script_cve_id(
    "CVE-2021-40733",
    "CVE-2021-42266",
    "CVE-2021-42267",
    "CVE-2021-42268",
    "CVE-2021-42269",
    "CVE-2021-42270",
    "CVE-2021-42271",
    "CVE-2021-42272",
    "CVE-2021-42524",
    "CVE-2021-42525"
  );
  script_xref(name:"IAVA", value:"2021-A-0512-S");

  script_name(english:"Adobe Animate 22.x < 22.0.0 Multiple Vulnerabilities (APSB21-105)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Animate installed on remote macOS or Mac OS X host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Animate installed on the remote macOS or Mac OS X host is prior to 22.0.0. It is, therefore,
affected by multiple vulnerabilities as referenced in the apsb21-105 advisory.

  - Adobe Animate version 21.0.9 (and earlier) are affected by an out-of-bounds write vulnerability that could
    result in arbitrary code execution in the context of the current user. Exploitation of this issue requires
    user interaction in that a victim must open a malicious BMP file. (CVE-2021-42270, CVE-2021-42271,
    CVE-2021-42524)

  - Adobe Animate version 21.0.9 (and earlier) is affected by a memory corruption vulnerability due to
    insecure handling of a malicious .psd file, potentially resulting in arbitrary code execution in the
    context of the current user. User interaction is required to exploit this vulnerability. (CVE-2021-40733)

  - Adobe Animate version 21.0.9 (and earlier) is affected by a memory corruption vulnerability due to
    insecure handling of a malicious FLA file, potentially resulting in arbitrary code execution in the
    context of the current user. User interaction is required to exploit this vulnerability. (CVE-2021-42266,
    CVE-2021-42267)

  - Adobe Animate version 21.0.9 (and earlier) is affected by a Null pointer dereference vulnerability when
    parsing a specially crafted FLA file. An unauthenticated attacker could leverage this vulnerability to
    achieve an application denial-of-service in the context of the current user. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2021-42268)

  - Adobe Animate version 21.0.9 (and earlier) are affected by a use-after-free vulnerability in the
    processing of a malformed FLA file that could result in arbitrary code execution in the context of the
    current user. Exploitation of this issue requires user interaction in that a victim must open a malicious
    file. (CVE-2021-42269)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/125.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/416.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/476.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/787.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/788.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/animate/apsb21-105.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Animate version 22.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42271");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125, 416, 476, 787, 788);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:animate");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_animate_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Animate");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit('Host/MacOSX/Version');

var app_info = vcf::get_app_info(app:'Adobe Animate');

var constraints = [
  { 'min_version' : '21.0.0', 'fixed_version' : '22.0.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
