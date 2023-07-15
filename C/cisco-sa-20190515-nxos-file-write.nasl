#TRUSTED 876bbf65edac33e0505160f95b9bc3c67222e8b8c5d0153f66473be2243d433653c00235b01821af8f427f8040410133af3db600452fffc6068eea57a8549aeba491db89af7c684a6d9551a83259a9e9bdc95ebefc6fa0519c655f392552c59849dbc9fe8c7c0823f380990e797b7e954a5d0f3591e64fe747524f698670c5e6ca7b261c74a779aed8fdd490987768ca5e7955e534c201b5449cf9f85056af06d8814ff84e33e0b830f69fd9ea6408f4bf1e902b05b2bb6c9f24f4f4d7a10fc2d7368fbcb767f83e700cc734150c892910eb84dd590f896c25718ab2dab8307f1dc42a5b32eddccb4ba9df249ca1ff362e1485ce110e0620f318b1f57427a529cbf8b006bf16cdd41c1fcdafe23fe2390413543487e3e512d7d70da83791e5ccf6f238db08ee57b12d7c02265a52a59ad721d5b6f57057905a06e22b1098cad984a9d516417e0b7098b7eaf94daf59c4e226e62f3570f0afba7c69ff8eeafcc53894e97633ca88abf4e88339da9ec9badaf70eb02d7b256d469360300236bf8785b573e0ff8114653019f941b0135dc7a5f2d8fdeb7fd540aac6843b36eb0af8eb04552bcac662e8c2330f1c7c261d61654b09f53208822e07f32b1a9be95d882291038c0885cf442995b09e103b6e97a8d4da071eb2d14385f37ee2e06c2e1a2001d2c50b85747d0fe6663c88ff5c29782803d24f219db88622cefe907b1c98
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128419);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-1729");
  script_bugtraq_id(108378);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh76022");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj03856");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-file-write");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco NX-OS Software Arbitrary File Overwrite Vulnerability");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability in the CLI implementation
of a specific command used for image maintenance for Cisco NX-OS Software. An authenticated, local attacker can exploit
the vulnerability to overwrite any file on the file system including system files. These file overwrites by the
attacker are accomplished at the root privilege level. The vulnerability occurs because there is no verification of
user-input parameters and or digital-signature verification for image files when using a specific CLI command. An
attacker could exploit this vulnerability by authenticating to the device and issuing a command at the CLI. Because an
exploit could allow the attacker to overwrite any file on the disk, including system files, a denial of service (DoS)
condition could occur. The attacker must have valid administrator credentials for the affected device to exploit this
vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-file-write
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21a0adf7");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh76022");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj03856");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvh76022 and CSCvj03856");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1729");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if (product_info.device == 'Nexus' && product_info.model !~ '^(3[056]|9[05])[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '7.0(3)I7(5a)',
  '7.0(3)I4(8z)',
  '7.0(3)I4(8b)',
  '7.0(3)I4(8a)',
  '7.0(3)I4(8)',
  '7.0(3)I4(7)',
  '7.0(3)I4(6)',
  '7.0(3)I4(5)',
  '7.0(3)I4(4)',
  '7.0(3)I4(3)',
  '7.0(3)I4(2)',
  '7.0(3)I4(1)',
  '7.0(3)I3(1)',
  '7.0(3)I2(5)',
  '7.0(3)I2(4)',
  '7.0(3)I2(3)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2a)',
  '7.0(3)I2(2)',
  '7.0(3)I2(1a)',
  '7.0(3)I2(1)',
  '7.0(3)I1(3b)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3)',
  '7.0(3)I1(2)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1)',
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(3b)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3)',
  '7.0(3)F3(2)',
  '7.0(3)F3(1)',
  '7.0(3)F2(2)',
  '7.0(3)F2(1)',
  '7.0(3)F1(1)',
  '7.0(3)',
  '7.0(2)N1(1a)',
  '7.0(2)N1(1)',
  '7.0(2)I2(2c)',
  '7.0(1)N1(3)',
  '7.0(1)N1(1)',
  '7.0(0)N1(1)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvh76022 and CSCvj03856'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  switch_only:TRUE
);
