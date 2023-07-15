##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162407);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-30664");

  script_name(english:"Adobe Animate 21.x < 21.0.11 / 22.x < 22.0.6 A Vulnerability (APSB22-24)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Animate installed on remote macOS or Mac OS X host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Animate installed on the remote macOS or Mac OS X host is prior to 21.0.11 or 22.0.6. It is,
therefore, affected by a vulnerability as referenced in the apsb22-24 advisory.

  - Adobe Animate version 22.0.5 (and earlier) is affected by an out-of-bounds write vulnerability that could
    result in arbitrary code execution in the context of the current user. Exploitation of this issue requires
    user interaction in that a victim must open a malicious file. (CVE-2022-30664)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/animate/apsb22-24.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Animate version 21.0.11 or 22.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30664");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:animate");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_animate_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Animate");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit('Host/MacOSX/Version');

var app_info = vcf::get_app_info(app:'Adobe Animate');

var constraints = [
  { 'min_version' : '21.0.0', 'fixed_version' : '21.0.11' },
  { 'min_version' : '22.0.0', 'fixed_version' : '22.0.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
