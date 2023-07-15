#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135181);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/06");

  script_cve_id("CVE-2020-7263");
  script_xref(name:"MCAFEE-SB", value:"SB10314");
  script_xref(name:"IAVA", value:"2019-A-0396-S");
  script_xref(name:"IAVA", value:"2020-A-0171-S");

  script_name(english:"McAfee Endpoint Security for Windows 10.5.x / 10.6.x / 10.7.0.x Improper Access Control (SB10314)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an improper access control vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the McAfee Endpoint Security (ENS) for Windows installed on the remote Windows host is 10.5.x , 10.6.x,
or 10.7.0.x. It is, therefore, affected by an improper access control vulnerability in ESConfigTool.exe which allows
a local administrator to alter the ENS configuration up to and including disabling all protection offered by ENS via
insecurely implemented encryption of configuration for export and import.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kcm.trellix.com/corporate/index?page=content&id=SB10314");
  # https://docs.trellix.com/bundle/endpoint-security-v10-6-1-july-2020-update-release-notes/resource/prod-endpoint-security-v10-6-1-release-notes.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d7c6005");
  # https://docs.trellix.com/bundle/endpoint-security-v10-7-x-july-2020-update-release-notes/resource/prod-endpoint-security-v10-7-x-release-notes.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e60cf51");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Endpoint Security version 10.6.1.2014, 10.7.0.1961, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7263");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:endpoint_security");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_endpoint_security_installed.nbin");
  script_require_keys("installed_sw/McAfee Endpoint Security Platform", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'McAfee Endpoint Security Platform', win_local:TRUE);

var constraints = [  
  { 'min_version' : '10.6.0', 'fixed_version' : '10.6.1.2014', 'fixed_display' : '10.6.1.2014 / 10.7.0.1961' },
  { 'min_version' : '10.7.0', 'fixed_version' : '10.7.0.1961'}  
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
