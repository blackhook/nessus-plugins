#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149452);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2021-28571", "CVE-2021-28586", "CVE-2021-28587");
  script_xref(name:"IAVA", value:"2021-A-0235-S");

  script_name(english:"Adobe After Effects < 18.2 Multiple Vulnerabilities (APSB21-33)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe After Effects installed on the remote Windows host is prior to 18.2. It is, therefore,
affected by multiple vulnerabilities, including the following: 

  - An OS command injection vulnerability exists in Adobe After Effects. An attacker could exploit this to 
  execute arbitrary code on an affected system. (CVE-2021-28571)

  - An out-of-bounds write error exists in Adobe After Effects. An attacker can exploit this to execute 
  arbitrary code on an affected system. (CVE-2021-28586)

  - An out-of-bounds read error exists in Adobe After Effects. An attacker can exploit this to read arbitrary
  files on the file system. (CVE-2021-28587)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://helpx.adobe.com/security/products/after_effects/apsb21-33.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c286ebf5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe After Effects version 18.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28586");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-28571");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:after_effects");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_after_effects_installed.nbin");
  script_require_keys("installed_sw/Adobe After Effects", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe After Effects', win_local:TRUE);
var constraints = [
  { 'fixed_version' : '18.2', 'fixed_display':'See vendor advisory'}
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);
