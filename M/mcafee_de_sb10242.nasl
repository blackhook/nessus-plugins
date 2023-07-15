#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(111531);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/07");

  script_cve_id("CVE-2018-6686");
  script_bugtraq_id(104916);
  script_xref(name:"IAVB", value:"2018-B-0097-S");
  script_xref(name:"MCAFEE-SB", value:"SB10242");

  script_name(english:"McAfee Drive Encryption 7.1 < 7.1.3 HF1241165 or 7.2.x < 7.2.6 Authentication Bypass vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an authentication bypass 
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of McAfee Drive Encryption
that is 7.1 < 7.1.3 HF1241165 or 7.2.x < 7.2.6 that is affected by an
authentication bypass vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10242");
  script_set_attribute(attribute:"solution", value:
"Update to 7.1.3 HF1241165, 7.2.6, or later");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6686");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:endpoint_encryption");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_endpoint_drive_encryption_installed.nbin");
  script_require_keys("installed_sw/McAfee Drive Encryption Agent", "SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"McAfee Drive Encryption Agent", win_local:TRUE);

constraints = [
  { "min_version" : "7.1.0", "fixed_version" : "7.1.3.635", "fixed_display":"7.1.3.635 (HF1241165)" },
  { "min_version" : "7.2.0", "fixed_version" : "7.2.6" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

