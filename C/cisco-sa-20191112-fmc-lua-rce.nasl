#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136719);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2019-15992");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96680");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191112-asa-ftd-lua-rce");
  script_xref(name:"IAVA", value:"2019-A-0425-S");

  script_name(english:"Cisco Firepower Management Center RCE (cisco-sa-20191112-asa-ftd-lua-rce)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported VDB version, Cisco Firepower Management Center is affected by a remote code execution
vulnerability. An attacker with valid administrative credentials can configure an Advanced Detector on the FMC web
interface and submit a malicious Lua script which, when pushed to a vulnerable managed FTD device, will escape the
scripting sandbox and execute arbitrary code with root privileges on the underlying Linux operating system of the FTD
device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191112-asa-ftd-lua-rce
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e82478b");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvr96680");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr96680");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15992");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_management_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

# Paranoid becausee it's only vulnerable if it manages a vulnerable FTD device
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

version = get_kb_item('Host/Cisco/firepower_mc/version');

# Check for hotfixes
patch_history = get_kb_item('Host/Cisco/firepower_mc/patch_history');
if (
    patch_history =~ "Sourcefire_3D_Defense_Center_S3_Hotfix_DQ-6.2.3.16-2" ||
    patch_history =~ "Cisco_Firepower_Mgmt_Center_Hotfix_AK-6.3.0.6-2" ||
    # This one does not match advisory, see: https://community.cisco.com/t5/network-security/determine-patch-version-to-resolve-fmc-vulnerability/m-p/4017887
    patch_history =~ "Cisco_Firepower_Mgmt_Center_Hotfix_AA-6.4.0.8" ||
    patch_history =~ "Cisco_Firepower_Mgmt_Center_Hotfix_B-6.5.0.2-2"
   )
  audit(AUDIT_HOST_NOT, 'affected as a relevant hotfix has been applied');


app_info = vcf::get_app_info(app:'Cisco Firepower Management Center', kb_ver:'Host/Cisco/firepower_mc/version');
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {'min_version': '0.0',     'fixed_version': '6.2.3.16'},
  {'min_version': '6.3.0',   'fixed_version': '6.3.0.6'},
  {'min_version': '6.4.0',   'fixed_version': '6.4.0.8'},
  {'min_version': '6.5.0',   'fixed_version': '6.5.0.2'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
