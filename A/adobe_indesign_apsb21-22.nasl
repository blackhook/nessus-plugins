#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149480);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/18");

  script_cve_id(
    "CVE-2021-21043",
    "CVE-2021-21098",
    "CVE-2021-21099",
    "CVE-2021-36004"
  );
  script_xref(name:"IAVA", value:"2021-A-0236-S");

  script_name(english:"Adobe InDesign < 16.2.1 Multiple Vulnerabilities (APSB21-22)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote Windows host is prior or equal to 16.2.1. It is, therefore,
affected by multiple out-of-bounds write vulnerabilities that could lead to code execution in the context of the current
user.  

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/indesign/apsb21-22.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InDesign version 16.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21099");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_indesign_installed.nbin");
  script_require_keys("installed_sw/Adobe InDesign", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe InDesign', win_local:TRUE);

var constraints = [ { 'fixed_version' : '16.1' , 'fixed_display' : '16.2.1' } ];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
