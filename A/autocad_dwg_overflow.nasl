#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73292);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/02");

  script_cve_id("CVE-2013-3665");

  script_name(english:"Autodesk AutoCAD DWG Buffer Overflow");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Autodesk AutoCAD installed that is
potentially affected by an error related to handling DWG files that
could lead to buffer overflows and possibly arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://vulners.com/binamuse/BINAMUSE:F12A08815586EE7A519144C52DC893AF");
  # https://knowledge.autodesk.com/support/autocad/downloads/caas/downloads/content/autodesk-C2-AE-autocad-C2-AE-code-execution-vulnerability--E2-80-93-security-hotfix.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9dc441c9");
  script_set_attribute(attribute:"solution", value:
"Apply the patch provided by the vendor. Note that :

  - AutoCAD 2011 Service Pack 2 is a pre-requisite to apply the patch.

  - AutoCAD 2012 Service Pack 2 is a pre-requisite to apply the patch.

  - AutoCAD 2013 Service Pack 2 is a pre-requisite to apply the patch.

  - AutoCAD 2014 Service Pack 1 contains the patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-3665");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_architecture");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_civil_3d");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_ecscad");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_electrical");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_lt");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_map_3d");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_mechanical");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_mep");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_p%26id");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_plant_3d");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_structural_detailing");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad_utility_design");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("autocad_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Autodesk AutoCAD");

  exit(0);

}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Autodesk AutoCAD', win_local:TRUE);

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '18.1.250.0' },
  { 'min_version' : '18.2', 'fixed_version' : '18.2.250.0' },
  { 'min_version' : '19.0', 'fixed_version' : '19.0.250.0' },
  { 'min_version' : '19.1', 'fixed_version' : '19.1.75.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);