#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157840);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2022-23204");
  script_xref(name:"IAVA", value:"2022-A-0067-S");

  script_name(english:"Adobe Premiere Rush <= 2.0 Privilege Escalation (APSB22-06)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Premiere Rush installed on the remote Windows host is affected by a privilege escalation vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Premiere Rush installed on the remote Windows host is version less than or equal to 2.0. It is,
therefore, affected by a privilege escalation vulnerability caused by an out-of-bounds read. 

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://helpx.adobe.com/security/products/premiere_rush/apsb22-06.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?027102b7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Premiere Rush version 2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23204");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_rush");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_premiere_rush_installed.nasl");
  script_require_keys("installed_sw/Adobe Premiere Rush", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Premiere Rush', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '2.1', 'fixed_display' : '2.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
