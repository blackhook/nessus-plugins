#TRUSTED 53268193af5819e3dc045df5a2ef56b6048ddaa2ddec88ac2894eea47ba579a41db56c44ea93ea998042a93f0ae7c18332bb85e051ef8ee4340d79ebbf5247cbf80bdd116262f937e5801f23b2703be9c0d6f23420a2581e48df6031dfd506034b146bb1a05874482a20d05ac66e298b773f2432c815dd7afd4ed2422bedc02e1de1d4ce43785e5b03f9619c1a1af1655134f66d71847645d491e5f48819b48e692db25476848c13f5721f7ddf8b0189cee46e34fd87af0dbefcce10533a6af5b8f225434d968a3637130407b1105a4bf105117585ef2c46133428e3536f8ee362afcc02ce38c145deaf49086eeb1932b64240a701a838b3edfd54c2a9851d743c2fdb00fd96c8af372428573c0ceb46331beae3139047934bea38eef0c88ea5b04b944e3273501abb7c1fa8f75c49b867bc44ddaf24fe5ea59cd5bd9c1ad07098fb1fb1eb60d2716a38b984b7a1d41627b3643ede7c32eefd2fd8df9051102f90b876ca45bf491684a8d32dd0bcc3217bbdbe449c6608a7acb88e7dbf428e7142b00a5eb6030fd22eb2e42852b2524d504b3659f96a6f9f99dde70e73e6bebcde2ef4b702e1666e8b1c1316ec90f15cd9ab036ea77f971b0f60b598a8a54725f2157987bff464da92dd0509bd0f78f367353b65f4ff088ea0441ff53918dc14f189e3fcd24c5304704dbe2772c3430283eee2d26f1d41d0c279cd2709625710
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128547);
  script_version("1.5");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-1965");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi15409");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn50393");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn50443");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn50446");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn52167");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190828-nxos-memleak-dos");
  script_xref(name:"IAVA", value:"2019-A-0317");

  script_name(english:"Cisco NX-OS Software Remote Management Memory Leak Denial of Service Vulnerability (CVE-2019-1965)");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by vulnerability in the Virtual Shell (VSH)
session management which could allow an authenticated, remote attacker to cause a VSH process to fail to delete upon
termination. This can lead to a build-up of VSH processes that overtime can deplete system memory. When there is no
system memory available, this can cause unexpected system behaviors and crashes. The vulnerability is due to the VSH
process not being properly deleted when a remote management connection to the device is disconnected. An attacker
could exploit this vulnerability by repeatedly performing a remote management connection to the device and terminating
the connection in an unexpected manner. A successful exploit could allow the attacker to cause the VSH processes to
fail to delete, which can lead to a system-wide denial of service (DoS) condition. The attacker must have valid user
credentials to log in to the device using the remote management connection.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190828-nxos-memleak-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?169b4cec");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi15409");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn50393");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn50443");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn50446");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn52167");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi15409, CSCvn50393, CSCvn50443, CSCvn50446,
and CSCvn52167");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1965");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/06");

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

cbi = '';

if ('MDS' >< product_info.device && product_info.model =~ '^90[0-9][0-9]')
  cbi = 'CSCvn50393';
if ('UCS' >< product_info.device && product_info.model =~ '^(6[23])[0-9][0-9]')
  cbi = 'CSCvn52167';
else if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^(3[056]|90)[0-9][0-9]')
    cbi = 'CSCvi15409';
  else if (product_info.model =~ '^(5[56]|60)[0-9][0-9]')
    cbi = 'CSCvn50446';
  else if (product_info.model =~ '^(7[07])[0-9][0-9]')
    cbi = 'CSCvn50443';
  else audit(AUDIT_HOST_NOT, 'affected');
}
else audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '5.0(4b)',
  '5.0(4c)',
  '5.0(4d)',
  '5.0(7)',
  '5.0(8)',
  '5.0(8a)',
  '5.2(1)',
  '5.2(3a)',
  '5.2(4)',
  '5.2(5)',
  '5.2(7)',
  '5.2(9)',
  '5.2(3)',
  '5.2(9a)',
  '5.2(2s)',
  '5.2(6)',
  '5.2(6b)',
  '5.2(8)',
  '5.2(8a)',
  '5.2(6a)',
  '5.2(8b)',
  '5.2(8c)',
  '5.2(8d)',
  '5.2(8e)',
  '5.2(8f)',
  '5.2(8g)',
  '5.2(8h)',
  '5.2(8i)',
  '6.1(1)',
  '6.1(2)',
  '6.1(3)',
  '6.1(4)',
  '6.1(4a)',
  '6.1(5)',
  '5.0(2)N2(1a)',
  '5.0(3)A1(1)',
  '5.0(3)A1(2)',
  '5.0(3)A1(2a)',
  '5.0(3)N1(1c)',
  '5.0(3)N1(1)',
  '5.0(3)N1(1a)',
  '5.0(3)N1(1b)',
  '5.0(3)N2(1)',
  '5.0(3)N2(2)',
  '5.0(3)N2(2a)',
  '5.0(3)N2(2b)',
  '5.0(3)U1(1)',
  '5.0(3)U1(1a)',
  '5.0(3)U1(1b)',
  '5.0(3)U1(2)',
  '5.0(3)U1(2a)',
  '5.0(3)U1(1c)',
  '5.0(3)U2(1)',
  '5.0(3)U2(2)',
  '5.0(3)U2(2c)',
  '5.0(3)U2(2d)',
  '5.0(3)U3(1)',
  '5.0(3)U3(2)',
  '5.0(3)U3(2a)',
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
  '5.1(3)N1(1)',
  '5.1(3)N1(1a)',
  '5.1(3)N2(1)',
  '5.1(3)N2(1a)',
  '5.1(3)N2(1b)',
  '5.1(3)N2(1c)',
  '5.2(1)N1(1)',
  '5.2(1)N1(1a)',
  '5.2(1)N1(1b)',
  '5.2(1)N1(2)',
  '5.2(1)N1(2a)',
  '5.2(1)N1(3)',
  '5.2(1)N1(4)',
  '5.2(1)N1(5)',
  '5.2(1)N1(6)',
  '5.2(1)N1(7)',
  '5.2(1)N1(8a)',
  '5.2(1)N1(8)',
  '5.2(1)N1(8b)',
  '5.2(1)N1(9)',
  '5.2(1)N1(9a)',
  '5.2(1)N1(9b)',
  '6.0(1)',
  '6.0(2)',
  '6.0(3)',
  '6.0(4)',
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
  '6.0(2)A6(1a)',
  '6.0(2)A6(2a)',
  '6.0(2)A6(3a)',
  '6.0(2)A6(4a)',
  '6.0(2)A6(5a)',
  '6.0(2)A6(5b)',
  '6.0(2)A6(6)',
  '6.0(2)A6(7)',
  '6.0(2)A6(8)',
  '6.0(2)A7(1a)',
  '6.0(2)A7(2)',
  '6.0(2)A7(2a)',
  '6.0(2)A8(2)',
  '6.0(2)A8(3)',
  '6.0(2)A8(4a)',
  '6.0(2)A8(5)',
  '6.0(2)A8(6)',
  '6.0(2)A8(7)',
  '6.0(2)A8(7a)',
  '6.0(2)A8(7b)',
  '6.0(2)A8(8)',
  '6.0(2)A8(9)',
  '6.0(2)A8(10a)',
  '6.0(2)A8(10)',
  '6.0(2)N1(1)',
  '6.0(2)N1(2)',
  '6.0(2)N1(2a)',
  '6.0(2)N1(1a)',
  '6.0(2)N2(1)',
  '6.0(2)N2(1b)',
  '6.0(2)N2(2)',
  '6.0(2)N2(3)',
  '6.0(2)N2(4)',
  '6.0(2)N2(5)',
  '6.0(2)N2(5a)',
  '6.0(2)N2(6)',
  '6.0(2)N2(7)',
  '6.0(2)N2(5b)',
  '6.0(2)U1(1)',
  '6.0(2)U1(2)',
  '6.0(2)U1(1a)',
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
  '6.0(2)U6(6)',
  '6.0(2)U6(7)',
  '6.0(2)U6(8)',
  '6.0(2)U6(5a)',
  '6.0(2)U6(5b)',
  '6.0(2)U6(5c)',
  '6.0(2)U6(9)',
  '6.0(2)U6(10)',
  '6.1(2)I1(3)',
  '6.1(2)I1(2)',
  '6.1(2)I2(1)',
  '6.1(2)I2(2)',
  '6.1(2)I2(2a)',
  '6.1(2)I2(3)',
  '6.1(2)I2(2b)',
  '6.1(2)I3(1)',
  '6.1(2)I3(2)',
  '6.1(2)I3(3)',
  '6.1(2)I3(4)',
  '6.1(2)I3(3a)',
  '6.1(2)I3(4a)',
  '6.1(2)I3(4b)',
  '6.1(2)I3(4c)',
  '6.1(2)I3(4d)',
  '6.1(2)I3(4e)',
  '6.1(2)I3(5)',
  '6.1(2)I3(5b)',
  '6.2(2)',
  '6.2(2a)',
  '6.2(6)',
  '6.2(6b)',
  '6.2(8)',
  '6.2(8a)',
  '6.2(8b)',
  '6.2(10)',
  '6.2(12)',
  '6.2(18)',
  '6.2(16)',
  '6.2(14b)',
  '6.2(14)',
  '6.2(14a)',
  '6.2(6a)',
  '6.2(20)',
  '6.2(1)',
  '6.2(3)',
  '6.2(5)',
  '6.2(5a)',
  '6.2(5b)',
  '6.2(7)',
  '6.2(9)',
  '6.2(9a)',
  '6.2(9b)',
  '6.2(9c)',
  '6.2(11)',
  '6.2(11b)',
  '6.2(11c)',
  '6.2(11d)',
  '6.2(11e)',
  '6.2(13)',
  '6.2(13a)',
  '6.2(13b)',
  '6.2(15)',
  '6.2(17)',
  '6.2(19)',
  '6.2(21)',
  '6.2(23)',
  '6.2(20a)',
  '6.2(25)',
  '6.2(17a)',
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
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(5)',
  '7.0(3)I1(1)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(2)',
  '7.0(3)I1(3)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3b)',
  '7.0(3)I1(1z)',
  '7.0(3)I2(2a)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(3)',
  '7.0(3)I2(4)',
  '7.0(3)I2(5)',
  '7.0(3)I2(1a)',
  '7.0(3)I2(2)',
  '7.0(3)I2(2r)',
  '7.0(3)I2(2s)',
  '7.0(3)I2(2v)',
  '7.0(3)I2(2w)',
  '7.0(3)I2(2x)',
  '7.0(3)I2(2y)',
  '7.0(3)I3(1)',
  '7.0(3)I4(1)',
  '7.0(3)I4(2)',
  '7.0(3)I4(3)',
  '7.0(3)I4(4)',
  '7.0(3)I4(5)',
  '7.0(3)I4(6)',
  '7.0(3)I4(7)',
  '7.0(3)I4(8)',
  '7.0(3)I4(8a)',
  '7.0(3)I4(8b)',
  '7.0(3)I4(1t)',
  '7.0(3)I4(6t)',
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
  '7.0(3)IX1(2)',
  '7.0(3)IX1(2a)',
  '7.0(3)N1(1)',
  '7.0(4)N1(1)',
  '7.0(4)N1(1a)',
  '7.0(5)N1(1)',
  '7.0(5)N1(1a)',
  '7.0(6)N1(1)',
  '7.0(6)N1(4s)',
  '7.0(6)N1(3s)',
  '7.0(6)N1(2s)',
  '7.0(7)N1(1)',
  '7.0(7)N1(1b)',
  '7.0(7)N1(1a)',
  '7.0(8)N1(1)',
  '7.0(8)N1(1a)',
  '7.1(0)N1(1a)',
  '7.1(0)N1(1b)',
  '7.1(0)N1(1)',
  '7.1(1)N1(1)',
  '7.1(1)N1(1a)',
  '7.1(2)N1(1)',
  '7.1(2)N1(1a)',
  '7.1(3)N1(1)',
  '7.1(3)N1(2)',
  '7.1(3)N1(5)',
  '7.1(3)N1(4)',
  '7.1(3)N1(3)',
  '7.1(3)N1(2a)',
  '7.1(4)N1(1)',
  '7.1(4)N1(1d)',
  '7.1(4)N1(1c)',
  '7.1(4)N1(1a)',
  '7.1(5)N1(1)',
  '7.2(0)D1(1)',
  '7.2(0)N1(1)',
  '7.2(1)D1(1)',
  '7.2(1)N1(1)',
  '7.2(2)D1(2)',
  '7.2(2)D1(1)',
  '7.2(2)D1(3)',
  '7.2(2)D1(4)',
  '7.3(0)D1(1)',
  '7.3(0)DX(1)',
  '7.3(0)DY(1)',
  '7.3(0)N1(1)',
  '7.3(0)N1(1b)',
  '7.3(0)N1(1a)',
  '7.3(1)D1(1)',
  '7.3(1)DY(1)',
  '7.3(1)N1(1)',
  '7.3(2)D1(1)',
  '7.3(2)D1(2)',
  '7.3(2)D1(3)',
  '7.3(2)D1(3a)',
  '7.3(2)N1(1)',
  '7.3(2)N1(1b)',
  '7.3(2)N1(1c)',
  '7.3(3)N1(1)',
  '8.0(1)',
  '8.1(1)',
  '8.1(2)',
  '8.1(2a)',
  '8.1(1a)',
  '8.1(1b)',
  '8.2(1)',
  '8.2(2)',
  '8.3(1)',
  '8.3(2)',
  '7.3(4)N1(1)',
  '7.3(4)N1(1a)',
  '7.3(3)D1(1)',
  '7.0(3)IA7(1)',
  '7.0(3)IA7(2)',
  '7.0(3)IC4(4)',
  '7.0(3)IM3(1)',
  '7.0(3)IM3(2)',
  '7.0(3)IM3(2a)',
  '7.0(3)IM3(2b)',
  '7.0(3)IM3(3)',
  '7.0(3)IM7(2)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  switch_only:TRUE
);
