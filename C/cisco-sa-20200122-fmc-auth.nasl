#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133261);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2019-16028");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr95287");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200122-fmc-auth");
  script_xref(name:"IAVA", value:"2020-A-0042-S");

  script_name(english:"Cisco Firepower Management Center Lightweight Directory Access Protocol Authentication Bypass (cisco-sa-20200122-fmc-auth)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Management Center is affected by an authentication bypass
vulnerability in the web-based management interface. This is due to improper handling of Lightweight Directory Access
Protocol (LDAP) authentication responses from an external authentication server. An unauthenticated, remote attacker
can exploit this, by sending crafted HTTP requests to an affected device, in order to bypass authentication and execute
arbitrary actions with administrative privileges on an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200122-fmc-auth
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c379a9e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr95287");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr95287");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16028");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_management_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('audit.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

# Check for hotfixes
patch_history = get_kb_item('Host/Cisco/firepower_mc/patch_history');
if (
    patch_history =~ "Sourcefire_3D_Defense_Center_S3_Hotfix_ES-6.1.0.8-2" ||
    patch_history =~ "Sourcefire_3D_Defense_Center_S3_Hotfix_DO-6.2.3.16-3" ||
    patch_history =~ "Cisco_Firepower_Mgmt_Center_Hotfix_AI-6.3.0.6-2" ||
    patch_history =~ "Cisco_Firepower_Mgmt_Center_Hotfix_U-6.4.0.7-2" ||
    patch_history =~ "Cisco_Firepower_Mgmt_Center_Hotfix_T-6.4.0.5-1"
   )
  audit(AUDIT_HOST_NOT, 'affected as a relevant hotfix has been applied');

app_info = vcf::get_app_info(app:'Cisco Firepower Management Center', kb_ver:'Host/Cisco/firepower_mc/version');

vcf::check_granularity(app_info:app_info, sig_segments:3);
# Replace - with . for vcf
app_info['version'] = ereg_replace(string:app_info['version'], pattern:"-", replace: ".");
# Re-parse version following replacement
app_info['parsed_version'] = vcf::parse_version(app_info['version']);

fix_6_2_3 = '6.2.3.16 or Sourcefire_3D_Defense_Center_S3_Hotfix_DO-6.2.3.16-3.sh.REL.tar';

constraints = [
  {'min_version' : '0.0.0', 'fixed_version' : '6.1.0', 'fixed_display' : fix_6_2_3},
  {'min_version' : '6.2.0', 'fixed_version' : '6.2.3.16', 'fixed_display' : fix_6_2_3},
  {'min_version' : '6.1.0', 'fixed_version' : '6.1.0.8.2', 'fixed_display' : 'Sourcefire_3D_Defense_Center_S3_Hotfix_ES-6.1.0.8-2.sh or ' + fix_6_2_3},
  {'min_version' : '6.3.0', 'fixed_version' : '6.3.0.6', 'fixed_display' : '6.3.0.6 or Cisco_Firepower_Mgmt_Center_Hotfix_AI-6.3.0.6-2.sh.REL.tar'},
  {'min_version' : '6.4.0',
    'fixed_version' : '6.4.0.7',
    'fixed_display' : '6.4.0.7 or Cisco_Firepower_Mgmt_Center_Hotfix_U-6.4.0.7-2.sh.REL.tar (for releases 6.4.0.5 and' +
        ' later) or Cisco_Firepower_Mgmt_Center_Hotfix_T-6.4.0.5-1.sh.REL.tar (for releases 6.4.0.4 and earlier)'},
  {'min_version' : '6.5.0', 'fixed_version' : '6.5.0.1', 'fixed_display' : '6.5.0.2'},
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
