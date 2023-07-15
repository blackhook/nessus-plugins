#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(174000);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/27");

  script_cve_id("CVE-2023-27909", "CVE-2023-27910", "CVE-2023-27911");
  script_xref(name:"IAVA", value:"2023-A-0172");

  script_name(english:"Autodesk FBX-SDK library < 2020.3.4 Multiple Vulnerabilities (ADSK-SA-2023-0004)");

  script_set_attribute(attribute:"synopsis", value:
"The Autodesk FBX-SDK library installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Autodesk FBX-SDK library installed on the remote host is prior to 2020.3.4. It is, therefore, affected
by multiple vulnerabilities:

  - An Out-Of-Bounds Write Vulnerability in Autodesk FBX SDK version 2020 or prior may lead to code execution through
    maliciously crafted FBX files or information disclosure. ()

  - A user may be tricked into opening a malicious FBX file that may exploit a stack buffer overflow vulnerability in
    Autodesk FBX SDK 2020 or prior which may lead to code execution. (CVE-2023-27910)
  
  - A user may be tricked into opening a malicious FBX file that may exploit a heap buffer overflow vulnerability in
    Autodesk FBX SDK 2020 or prior which may lead to code execution. (CVE-2023-27911)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2023-0004");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Autodesk FBX-SDK library version 2020.3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27911");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:fbx_software_development_kit");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("autodesk_fbx-sdk_detect_win.nbin");
  script_require_keys("installed_sw/FBX SDK");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'FBX SDK');

var constraints = [
  { 'fixed_version' : '2020.3.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
