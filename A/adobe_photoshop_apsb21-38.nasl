#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150451);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/26");

  script_cve_id("CVE-2021-28582", "CVE-2021-28624");
  script_xref(name:"IAVA", value:"2021-A-0270-S");

  script_name(english:"Adobe Photoshop 21.x < 21.2.9 / 22.x < 22.4.2 Multiple Vulnerabilities (APSB21-38)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Photoshop installed on remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop installed on the remote Windows host is prior to 21.2.8/22.4.1. It is,
therefore, affected by multiple vulnerabilities as referenced in the apsb21-38 advisory which allows a remote
attacker to execute arbitrary code on the target system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb21-38.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop version 21.2.9/22.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28624");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_photoshop_installed.nasl");
  script_require_keys("installed_sw/Adobe Photoshop", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Photoshop', win_local:TRUE);

var constraints = [
  { 'min_version' : '21.0.0', 'fixed_version' : '21.2.9' },
  { 'min_version' : '22.0.0', 'fixed_version' : '22.4.2' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
 severity:SECURITY_HOLE
);
