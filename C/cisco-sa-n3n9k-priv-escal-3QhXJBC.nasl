#TRUSTED 9f566fe9f63a4a9da784f9a062cd58810360cf524ca6d48f6ed0555e1a6e0f5feeb014c636aed00197f58aa4998ed63feb1b40aab52a555691cf154672b122ace2cab05038d53051763053bc53e3abd9cb84049c503ab838391e3b79950bac3389cfc6a584335582cff2d6ab420238724499e7e6c099a95aeb2a712eb436214070579d33e832db402aae24a0d1052e57adb1cae6f0d72860b6b8d96625bc9ad41356cd0f063ab6e67591048df7ec568025085f517ba98cd1e7d1599b6d9efd16fa5e78addff1e5394295d084b3e38ae07a3f2ef3f6553660e21f15c1d978b9c29fae8603fcad660e583228b0ead7e50a451eeefb0b3a25db347163f3a59481e8f7dc49d42c1d61f2de4e4d0bd550484fca03bf1c13e7bbf00d0e2486ddb988badeb8cf2bd4ddc733cfa97071f5730f84ac4d570d82f4e82a4b26099cb36dd5132315753a1d1acfa3528cd3f508ca51d55c762313a7bf8db13ad339af7c22820a2c2f3ee633dfcb3ce902cbc40fe2335a61526f0fafa5f8c30e84d4e244712bc652642d2c8b43bfdbc5fdbe93c00b50c61ae5061103dff2da935f5ad63a088b48a1cf8ac6336b7e40584b882813a3c859d8c1571b79a12f66f751a08607103670e3713bfb1324dd21cb718c6eda8f10b21dc284b434c843baf97959a0ddeeb4e8b14f36b3f7659f2ddfad5a609cf545f3f06ca1c0c916b5604f971a6c206d95ac
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140097);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/12");

  script_cve_id("CVE-2020-3394");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt77885");
  script_xref(name:"CISCO-SA", value:"cisco-sa-n3n9k-priv-escal-3QhXJBC");
  script_xref(name:"IAVA", value:"2020-A-0394");

  script_name(english:"Cisco Nexus 3000 and 9000 Series Switches Privilege Escalation (cisco-sa-n3n9k-priv-escal-3QhXJBC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability in the Enable Secret
feature due to a logic error in the implementation of the enable command. An authenticated, local attacker can exploit
this, by logging in to the device and issuing the enable command, in order to gain full administrative privileges
without using the enable password.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n3n9k-priv-escal-3QhXJBC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c634fbd");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74239");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt77885");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt77885");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3394");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(285);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ "^[39][0-9]{3}")
  audit(AUDIT_HOST_NOT, 'an affected model');

#  not 9k in ACI mode
if (!(empty_or_null(get_kb_list('Host/aci/*'))))
    audit(AUDIT_HOST_NOT, 'an affected model due to ACI mode');

version_list=make_list(
  '9.2(1)',
  '9.2(2)',
  '9.2(2t)',
  '9.2(2v)',
  '9.2(3)',
  '9.2(3y)',
  '9.2(4)',
  '9.3(1)',
  '9.3(1z)',
  '9.3(2)',
  '9.3(3)'
);

workarounds = make_list(CISCO_WORKAROUNDS['feature_privilege'], CISCO_WORKAROUNDS['enable_secret']);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt77885',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  require_all_workarounds:TRUE
);



