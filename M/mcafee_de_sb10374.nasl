#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155446);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/19");

  script_cve_id("CVE-2021-31853");
  script_xref(name:"MCAFEE-SB", value:"SB10374");
  script_xref(name:"IAVB", value:"2021-B-0064");

  script_name(english:"McAfee Drive Encryption < 7.3.0 HF2 DLL Hijacking (SB10374)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a DLL hijacking vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of McAfee Drive Encryption prior to 7.3.0 HF2. It is, therefore, affected by a
DLL search order hijacking vulnerability that allows local users to execute arbitrary code and escalate privileges via
execution from a compromised folder.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10374");
  script_set_attribute(attribute:"solution", value:
"Update to McAfee Drive Encryption 7.3.0 HF2 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31853");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:drive_encryption");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_endpoint_drive_encryption_installed.nbin");
  script_require_keys("installed_sw/McAfee Drive Encryption Agent", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'McAfee Drive Encryption Agent', win_local:TRUE);

# https://kc.mcafee.com/corporate/index?page=content&id=KB79422 maps hotfix->version numbers
var constraints = [
  { 'fixed_version' : '7.3.0.183', 'fixed_display':'7.3.0.183 (HF2)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

