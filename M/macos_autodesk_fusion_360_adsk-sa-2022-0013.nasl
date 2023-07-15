##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162497);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/09");

  script_cve_id("CVE-2022-27873");
  script_xref(name:"IAVB", value:"2022-B-0017");

  script_name(english:"macOS Autodesk Fusion 360 < 2.0.12888 XXE (adsk-sa-2022-0013)");

  script_set_attribute(attribute:"synopsis", value:
"Autodesk Fusion 360 installed on remote macOS or Mac OS X host is affected by an XML external entity vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Autodesk Fusion 360 installed on the remote macOS or Mac OS X host is prior to 2.0.12888. It is, therefore,
affected by an XML external entity (XXE) vulnerability that can cause a victim to perform arbitrary HTTP requests when
parsing a malicious SVG file. An unauthenticated, remote attacker can exploit this to disclose sensitive information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2022-0013");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Autodesk Fusion 360 version 2.0.12888 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27873");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:autodesk:fusion_360");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macos_autodesk_fusion_360_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Autodesk Fusion 360");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit('Host/MacOSX/Version');

var app_info = vcf::get_app_info(app:'Autodesk Fusion 360');

var constraints = [
  { 'fixed_version' : '2.0.12888' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
