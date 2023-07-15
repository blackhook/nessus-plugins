#TRUSTED 31df1fd072b32ee4b70d6838bacf8b1b15a5738d3e142da3f9e293418091e9b08edd8f108e21be9ad8bfc522ec3c3e4312f33cba859af4dff32a40d3230b3d854a9af59a57d6576b0c9e8454152dad1f6e5d4db2d6affd207927e049700f24550d1d66cb8d9f6878cde708c2469a216ffab061d1082a7b257c2d64bc18480afa4ea471c05cc9205528931fc11a260dca6ee4a7d26968f5545529fdb6fa75d846e515aa9939cb822925c46e8bfc96c97b8b2c7adc3f06ca9189197c72d269fc66d167609dc5564f5ae7b692d583e677da7a8684308aea459561da0591e71de8d9563a52d83fcc3948ec91fedd1e1d883d311acc37ea4e6ebcbcc0ab2e62a2323cd5745dc81decfd9eed6e147f7f86e4596dddfbdf33f40df7db42559356a56e1ccde1fee4c97f17447293ed15cf910b1ef61690dbfebbebc21e687acf734898bbe86ce5700395d17fcbeb6ce56550849bb4d09793caa34aca3224c71d7e50727d8ee2367395ade6a9a468a813b8db9e58cfca3f41acf83b8f6a559956d7d78301b08f2db2fea2c3a86461830d2c76aa2e8828a1377fa392a482a038dbb910b1e676a035db49760cdccf70c39733f9fb18e44aa24c41b55d0684c608645fc46c9d4612d8992e44ba06bfb4da7bf8851cd2c47ab95893924cc15520e62e9ecdfa07e39b9800b5ac0946027621353c12d1af79f4d3a4973b74b8887c2c3ef62b1ef0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129588);
  script_version("1.7");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-12717");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo19193");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk76030");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-nxos-vman-cmd-inj");
  script_xref(name:"IAVA", value:"2019-A-0353");

  script_name(english:"Cisco NX-OS Software Command Injection Vulnerability (cisco-sa-20190925-nxos-vman-cmd-inj)");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability in a CLI command related to
the virtualization manager (VMAN) in Cisco NX-OS Software could allow an authenticated, local attacker to execute
arbitrary commands on the underlying Linux operating system with root privileges. The vulnerability is due to
insufficient validation of arguments passed to a specific VMAN CLI command on an affected device. An attacker could
exploit this vulnerability by including malicious input as the argument of an affected command. A successful exploit
could allow the attacker to execute arbitrary commands on the underlying Linux operating system with root privileges,
which may lead to complete system compromise. An attacker would need valid administrator credentials to exploit this
vulnerability. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-nxos-vman-cmd-inj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e216f7e1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo19193");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk76030");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo19193, and CSCvk76030");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12717");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

if ('Nexus' >!< product_info.device) audit(AUDIT_HOST_NOT, 'affected');
cbi = '';

if (product_info.model =~ '^(3[056]|9[05])[0-9][0-9]')
  cbi = 'CSCvo19193';
else if (product_info.model =~ '^(5[56]|60|7[70])[0-9][0-9]')
  cbi = 'CSCvk76030';
else audit(AUDIT_HOST_NOT, 'affected');

vuln_list = [
'5.0(3)A1(1)',
'5.0(3)A1(2)',
'5.0(3)A1(2a)',
'5.0(3)U4(1)',
'5.0(3)U5(1)',
'5.0(3)U5(1a)',
'5.0(3)U5(1b)',
'5.0(3)U5(1c)',
'5.0(3)U5(1d)',
'5.0(3)U5(1e)',
'5.0(3)U5(1f)',
'5.0(3)U5(1g)',
'5.0(3)U5(1h)',
'5.0(3)U5(1i)',
'5.0(3)U5(1j)',
'6.0(2)A1(1)',
'6.0(2)A1(1a)',
'6.0(2)A1(1b)',
'6.0(2)A1(1c)',
'6.0(2)A1(1d)',
'6.0(2)A1(1e)',
'6.0(2)A1(1f)',
'6.0(2)A1(2d)',
'6.0(2)A3(1)',
'6.0(2)A3(2)',
'6.0(2)A3(4)',
'6.0(2)A4(1)',
'6.0(2)A4(2)',
'6.0(2)A4(3)',
'6.0(2)A4(4)',
'6.0(2)A4(5)',
'6.0(2)A4(6)',
'6.0(2)A6(1)',
'6.0(2)A6(1a)',
'6.0(2)A6(2)',
'6.0(2)A6(2a)',
'6.0(2)A6(3)',
'6.0(2)A6(3a)',
'6.0(2)A6(4)',
'6.0(2)A6(4a)',
'6.0(2)A6(5)',
'6.0(2)A6(5a)',
'6.0(2)A6(5b)',
'6.0(2)A6(6)',
'6.0(2)A6(7)',
'6.0(2)A6(8)',
'6.0(2)A7(1)',
'6.0(2)A7(1a)',
'6.0(2)A7(2)',
'6.0(2)A7(2a)',
'6.0(2)A8(1)',
'6.0(2)A8(10)',
'6.0(2)A8(10a)',
'6.0(2)A8(11)',
'6.0(2)A8(11a)',
'6.0(2)A8(11b)',
'6.0(2)A8(2)',
'6.0(2)A8(3)',
'6.0(2)A8(4)',
'6.0(2)A8(4a)',
'6.0(2)A8(5)',
'6.0(2)A8(6)',
'6.0(2)A8(7)',
'6.0(2)A8(7a)',
'6.0(2)A8(7b)',
'6.0(2)A8(8)',
'6.0(2)A8(9)',
'6.0(2)N1(1)',
'6.0(2)N1(1a)',
'6.0(2)N1(2)',
'6.0(2)N1(2a)',
'6.0(2)N2(1)',
'6.0(2)N2(1b)',
'6.0(2)N2(2)',
'6.0(2)N2(3)',
'6.0(2)N2(4)',
'6.0(2)N2(5)',
'6.0(2)N2(5a)',
'6.0(2)N2(5b)',
'6.0(2)N2(6)',
'6.0(2)N2(7)',
'6.0(2)U1(1)',
'6.0(2)U1(1a)',
'6.0(2)U1(2)',
'6.0(2)U1(3)',
'6.0(2)U1(4)',
'6.0(2)U2(1)',
'6.0(2)U2(2)',
'6.0(2)U2(3)',
'6.0(2)U2(4)',
'6.0(2)U2(5)',
'6.0(2)U2(6)',
'6.0(2)U3(1)',
'6.0(2)U3(2)',
'6.0(2)U3(3)',
'6.0(2)U3(4)',
'6.0(2)U3(5)',
'6.0(2)U3(6)',
'6.0(2)U3(7)',
'6.0(2)U3(8)',
'6.0(2)U3(9)',
'6.0(2)U4(1)',
'6.0(2)U4(2)',
'6.0(2)U4(3)',
'6.0(2)U4(4)',
'6.0(2)U5(1)',
'6.0(2)U5(2)',
'6.0(2)U5(3)',
'6.0(2)U5(4)',
'6.0(2)U6(1)',
'6.0(2)U6(10)',
'6.0(2)U6(1a)',
'6.0(2)U6(2)',
'6.0(2)U6(2a)',
'6.0(2)U6(3)',
'6.0(2)U6(3a)',
'6.0(2)U6(4)',
'6.0(2)U6(4a)',
'6.0(2)U6(5)',
'6.0(2)U6(5a)',
'6.0(2)U6(5b)',
'6.0(2)U6(5c)',
'6.0(2)U6(6)',
'6.0(2)U6(7)',
'6.0(2)U6(8)',
'6.0(2)U6(9)',
'6.1(2)I1(2)',
'6.1(2)I1(3)',
'6.1(2)I2(1)',
'6.1(2)I2(2)',
'6.1(2)I2(2a)',
'6.1(2)I2(2b)',
'6.1(2)I2(3)',
'6.1(2)I3(1)',
'6.1(2)I3(2)',
'6.1(2)I3(3)',
'6.1(2)I3(3a)',
'6.1(2)I3(4)',
'6.1(2)I3(4a)',
'6.1(2)I3(4b)',
'6.1(2)I3(4c)',
'6.1(2)I3(4d)',
'6.1(2)I3(4e)',
'6.1(2)I3(5)',
'6.1(2)I3(5b)',
'6.2(10)',
'6.2(12)',
'6.2(14)',
'6.2(14a)',
'6.2(14b)',
'6.2(16)',
'6.2(18)',
'6.2(2)',
'6.2(20)',
'6.2(20a)',
'6.2(22)',
'6.2(2a)',
'6.2(6)',
'6.2(6a)',
'6.2(6b)',
'6.2(8)',
'6.2(8a)',
'6.2(8b)',
'7.0(0)N1(1)',
'7.0(1)N1(1)',
'7.0(2)N1(1)',
'7.0(3)F1(1)',
'7.0(3)F2(1)',
'7.0(3)F2(2)',
'7.0(3)F3(1)',
'7.0(3)F3(2)',
'7.0(3)F3(3)',
'7.0(3)F3(3a)',
'7.0(3)F3(3c)',
'7.0(3)F3(4)',
'7.0(3)F3(5)',
'7.0(3)I1(1)',
'7.0(3)I1(1a)',
'7.0(3)I1(1b)',
'7.0(3)I1(1z)',
'7.0(3)I1(2)',
'7.0(3)I1(3)',
'7.0(3)I1(3a)',
'7.0(3)I1(3b)',
'7.0(3)I2(1)',
'7.0(3)I2(1a)',
'7.0(3)I2(2)',
'7.0(3)I2(2a)',
'7.0(3)I2(2b)',
'7.0(3)I2(2c)',
'7.0(3)I2(2d)',
'7.0(3)I2(2e)',
'7.0(3)I2(2r)',
'7.0(3)I2(2s)',
'7.0(3)I2(2v)',
'7.0(3)I2(2w)',
'7.0(3)I2(2x)',
'7.0(3)I2(2y)',
'7.0(3)I2(3)',
'7.0(3)I2(4)',
'7.0(3)I2(5)',
'7.0(3)I3(1)',
'7.0(3)I4(1)',
'7.0(3)I4(1t)',
'7.0(3)I4(2)',
'7.0(3)I4(3)',
'7.0(3)I4(4)',
'7.0(3)I4(5)',
'7.0(3)I4(6)',
'7.0(3)I4(6t)',
'7.0(3)I4(7)',
'7.0(3)I4(8)',
'7.0(3)I4(8a)',
'7.0(3)I4(8b)',
'7.0(3)I4(8z)',
'7.0(3)I4(9)',
'7.0(3)I5(1)',
'7.0(3)I5(2)',
'7.0(3)I5(3)',
'7.0(3)I5(3a)',
'7.0(3)I5(3b)',
'7.0(3)I6(1)',
'7.0(3)I6(2)',
'7.0(3)I7(1)',
'7.0(3)I7(2)',
'7.0(3)I7(3)',
'7.0(3)I7(3z)',
'7.0(3)I7(4)',
'7.0(3)I7(5)',
'7.0(3)I7(5a)',
'7.0(3)IA7(1)',
'7.0(3)IA7(2)',
'7.0(3)IC4(4)',
'7.0(3)IM3(1)',
'7.0(3)IM3(2)',
'7.0(3)IM3(2a)',
'7.0(3)IM3(2b)',
'7.0(3)IM3(3)',
'7.0(3)IM7(2)',
'7.0(3)IX1(2)',
'7.0(3)IX1(2a)',
'7.0(3)N1(1)',
'7.0(4)N1(1)',
'7.0(4)N1(1a)',
'7.0(5)N1(1)',
'7.0(5)N1(1a)',
'7.0(6)N1(1)',
'7.0(6)N1(2s)',
'7.0(6)N1(3s)',
'7.0(6)N1(4s)',
'7.0(7)N1(1)',
'7.0(7)N1(1a)',
'7.0(7)N1(1b)',
'7.0(8)N1(1)',
'7.0(8)N1(1a)',
'7.1(0)N1(1)',
'7.1(0)N1(1a)',
'7.1(0)N1(1b)',
'7.1(1)N1(1)',
'7.1(1)N1(1a)',
'7.1(2)N1(1)',
'7.1(2)N1(1a)',
'7.1(3)N1(1)',
'7.1(3)N1(2)',
'7.1(3)N1(2a)',
'7.1(3)N1(3)',
'7.1(3)N1(4)',
'7.1(3)N1(5)',
'7.1(4)N1(1)',
'7.1(4)N1(1a)',
'7.1(4)N1(1c)',
'7.1(4)N1(1d)',
'7.1(5)N1(1)',
'7.1(5)N1(1b)',
'7.2(0)D1(1)',
'7.2(0)N1(1)',
'7.2(1)D1(1)',
'7.2(1)N1(1)',
'7.2(2)D1(1)',
'7.2(2)D1(2)',
'7.2(2)D1(3)',
'7.2(2)D1(4)',
'7.3(0)D1(1)',
'7.3(0)DX(1)',
'7.3(0)N1(1)',
'7.3(0)N1(1a)',
'7.3(0)N1(1b)',
'7.3(1)D1(1)',
'7.3(1)N1(1)',
'7.3(2)D1(1)',
'7.3(2)D1(2)',
'7.3(2)D1(3)',
'7.3(2)D1(3a)',
'7.3(2)N1(1)',
'7.3(2)N1(1b)',
'7.3(2)N1(1c)',
'7.3(3)D1(1)',
'7.3(3)N1(1)',
'7.3(4)D1(1)',
'7.3(4)N1(1)',
'7.3(4)N1(1a)',
'9.2(1)',
'9.2(2)',
'9.2(2t)'
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_list,
  switch_only:TRUE
);
