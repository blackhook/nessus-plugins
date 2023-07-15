#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136667);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/19");

  script_cve_id("CVE-2020-7264");
  script_xref(name:"MCAFEE-SB", value:"SB10316");
  script_xref(name:"IAVA", value:"2020-A-0202");

  script_name(english:"McAfee Endpoint Security for Windows 10.5.x / 10.6.x / 10.7.0.x Privilege Escalation (SB10316)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the McAfee Endpoint Security (ENS) for Windows 
installed on the remote Windows host is 10.5.x , 10.6.x, or 10.7.0.x. 
It is, therefore, affected by a privilege escalation vulnerability which allows
a malicious attacker the ability to delete files they do not have access to.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10316");
  script_set_attribute(attribute:"solution", value:
"Apply the workaround mentioned in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7264");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:endpoint_security");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_endpoint_security_installed.nbin");
  script_require_keys("installed_sw/McAfee Endpoint Security Platform", "SMB/Registry/Enumerated", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'McAfee Endpoint Security Platform', win_local:TRUE);

if (app_info['version'] !~ "^10\.(5|6)\." && app_info['version'] !~ "^10\.7\.0")
  audit(AUDIT_HOST_NOT, 'an affected version');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

constraints = [
  {
    'min_version':'10.5.0',
    'fixed_version':'10.7.0.1733',
    'fixed_display':'No fixed version is currently available, apply the workaround from the vendor advisory.'
  }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
