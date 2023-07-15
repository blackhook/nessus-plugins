#TRUSTED 66398af978516381f07e61fe43b8b071bd354a3273fd2ab1c8442bbb8b4ea57ef9aeca491b643f9cfa5adf0415a36c25ccd4e5945e914f35c83924bd7d89127e17c5b0b483fb90aef204064cb39382a3bc42574e4afb1e628686f5726a02a281eda0414bcdf327dd5762c5df846cf731d6113721bd20582773815fc665d07af963fdc02e6c6229f95c1d6e7dca5f0a28587f7449ee4586931be67ce3d68aae211df6d04560ab19e532fbb6007d9accb310830d5c713574a3b1a0631b85d821b1922b65f0411250b18794cb47703b812a2aaaf6724300816062fee6052c5ff214f26d1f12999a2e2869a2e5755695864fa53e4859ca824dd74d64a8b94059fa3ff4906dcb634d8094c26f1ee9ad5d8ced323733eef03ec8ca7853c4c8f8070d2f7cb847e130191af8cef1f9efa26720cbe386e2f6bd1ec1d1aa967e65f400165fa22ebbd25407e91ac123133b2cf5d01ac5cc596ee5b1f76387a20fc81eaaea86ac144fd2fe0b1d5492077988c3bcde3c0188e7d0c432fc67585e0803416bbedc0857bc6b23657c39108e397206adf47d8ace9f24fb39d713ce465cf89ae9af2c089d9d068d981f7b10f802a049eec31e9a28750f0efc884639bda76844dca5769894af7182c97966be668a4fa48435e36de83c65f224e247a45fa6baab76bb9b309cb9a61af8e0bfa3e7382ea3c7743d5ace1d509966846522b439f983961e6a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131700);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/25");

  script_cve_id("CVE-2019-1611");
  script_bugtraq_id(107381);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj63798");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj65666");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk65444");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk65482");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxos-cmdinj-1611");

  script_name(english:"Cisco NX-OS Software Command Injection (cisco-sa-20190306-nxos-cmdinj-1611)");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a command injection vulnerability due to
insufficient validation of arguments passed to certain CLI commands. An authenticated, local attacker with valid
administrator credentials can exploit this by including malicious input as the argument of an affected command in order
to execute arbitrary commands on the underlying operating system with elevated privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-cmdinj-1611
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?326bae04");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj63798");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj65666");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk65444");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk65482");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvj63798, CSCvj65666, CSCvk65444, CSCvk65482.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1611");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

cbi = '';
if(('MDS' >< product_info.device && product_info.model =~ '^90[0-9]{2}') ||
   ('Nexus' >< product_info.device && product_info.model =~ '^7[07][0-9]{2}'))
  cbi = 'CSCvj63798';
else if('Nexus' >< product_info.device)
{
  if(product_info.model =~ '^36[0-9]{2}' || product_info.model =~ '^95[0-9]{2}R')
    cbi = 'CSCvk65482';
  else if(product_info.model =~ '^[26]0[0-9]{2}' || product_info.model =~ '^5[56][0-9]{2}')
    cbi = 'CSCvk65444';
  else if(product_info.model =~ '^35[0-9]{2}' || product_info.model =~ '^[39]0[0-9]{2}')
    cbi = 'CSCvj65666';
}
else audit(AUDIT_HOST_NOT, 'affected');

version_list = make_list(
  '4.1(2)',
  '4.1(3)',
  '4.1(4)',
  '4.1(5)',
  '5.0(2a)',
  '5.0(3)',
  '5.0(5)',
  '5.0(1a)',
  '5.0(1b)',
  '5.0(4)',
  '5.0(4b)',
  '5.0(4c)',
  '5.0(4d)',
  '5.0(7)',
  '5.0(8)',
  '5.0(8a)',
  '4.2(2a)',
  '4.2(3)',
  '4.2(4)',
  '4.2(6)',
  '4.2(8)',
  '5.1(1)',
  '5.1(1a)',
  '5.1(3)',
  '5.1(4)',
  '5.1(5)',
  '5.1(6)',
  '5.2(1)',
  '5.2(3a)',
  '5.2(4)',
  '5.2(5)',
  '5.2(7)',
  '5.2(9)',
  '5.2(3)',
  '5.2(9a)',
  '5.2(2)',
  '5.2(2a)',
  '5.2(2d)',
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
  '6.1(3)S5',
  '6.1(3)S6',
  '6.1(5a)',
  '4.2(1)N1(1)',
  '4.2(1)N2(1)',
  '4.2(1)N2(1a)',
  '5.0(2)N1(1)',
  '5.0(2)N2(1)',
  '5.0(2)N2(1a)',
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
  '5.0(3)U1(1d)',
  '5.0(3)U1(2)',
  '5.0(3)U1(2a)',
  '5.0(3)U1(1c)',
  '5.0(3)U2(1)',
  '5.0(3)U2(2)',
  '5.0(3)U2(2a)',
  '5.0(3)U2(2b)',
  '5.0(3)U2(2c)',
  '5.0(3)U2(2d)',
  '5.0(3)U3(1)',
  '5.0(3)U3(2)',
  '5.0(3)U3(2a)',
  '5.0(3)U3(2b)',
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
  '6.0(2)U6(1)',
  '6.0(2)U6(2)',
  '6.0(2)U6(3)',
  '6.0(2)U6(4)',
  '6.0(2)U6(5)',
  '6.0(2)U6(6)',
  '6.0(2)U6(7)',
  '6.0(2)U6(8)',
  '6.0(2)U6(1a)',
  '6.0(2)U6(2a)',
  '6.0(2)U6(3a)',
  '6.0(2)U6(4a)',
  '6.0(2)U6(5a)',
  '6.0(2)U6(5b)',
  '6.0(2)U6(5c)',
  '6.0(2)U6(9)',
  '6.0(2)U6(10)',
  '6.1(2)I1(3)',
  '6.1(2)I1(1)',
  '6.1(2)I2(1)',
  '6.1(2)I2(2)',
  '6.1(2)I2(2a)',
  '6.1(2)I2(3)',
  '6.1(2)I2(2b)',
  '6.1(2)I3(1)',
  '6.1(2)I3(2)',
  '6.1(2)I3(3)',
  '6.1(2)I3(3.78)',
  '6.1(2)I3(4)',
  '6.1(2)I3(3a)',
  '6.1(2)I3(4a)',
  '6.1(2)I3(4b)',
  '6.1(2)I3(4c)',
  '6.1(2)I3(4d)',
  '6.1(2)I3(4e)',
  '6.1(2)I3(5)',
  '6.1(2)I3(5a)',
  '6.1(2)I3(5b)',
  '6.1(2)I3(3b)',
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
  '7.0(0)N1(1)',
  '7.0(1)N1(1)',
  '7.0(2)I2(2c)',
  '7.0(2)N1(1)',
  '7.0(2)N1(1a)',
  '7.0(3)F1(1)',
  '7.0(3)F2(1)',
  '7.0(3)F2(2)',
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)I1(1)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(2)',
  '7.0(3)I1(3)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3b)',
  '7.0(3)I2(2a)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(3)',
  '7.0(3)I2(4)',
  '7.0(3)I2(5)',
  '7.0(3)I2(1)',
  '7.0(3)I2(1a)',
  '7.0(3)I2(2)',
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
  '7.0(3)I4(8z)',
  '7.0(3)I5(1)',
  '7.0(3)I5(2)',
  '7.0(3)I6(1)',
  '7.0(3)I6(2)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)I7(4)',
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
  '7.0(6)N1(1c)',
  '7.0(7)N1(1)',
  '7.0(7)N1(1b)',
  '7.0(7)N1(1a)',
  '7.0(8)N1(1)',
  '7.0(8)N1(1a)',
  '7.1(0)N1(1a)',
  '7.1(0)N1(1b)',
  '7.1(0)N1(2)',
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
  '7.1(3)N1(1b)',
  '7.1(4)N1(1)',
  '7.1(4)N1(1d)',
  '7.1(4)N1(1c)',
  '7.1(4)N1(1a)',
  '7.1(4)N1(1e)',
  '7.1(5)N1(1)',
  '7.2(0)D1(1)',
  '7.2(0)N1(1)',
  '7.2(1)D1(1)',
  '7.2(1)N1(1)',
  '7.2(2)D1(2)',
  '7.2(2)D1(1)',
  '7.3(0)D1(1)',
  '7.3(0)DX(1)',
  '7.3(0)DY(1)',
  '7.3(0)N1(1)',
  '7.3(0)N1(1b)',
  '7.3(0)N1(1a)',
  '7.3(1)D1(1B)',
  '7.3(1)D1(1)',
  '7.3(1)DY(1)',
  '7.3(1)N1(0.1)',
  '7.3(1)N1(1)',
  '7.3(2)D1(1A)',
  '7.3(2)D1(1)',
  '7.3(2)D1(2)',
  '7.3(2)D1(3)',
  '7.3(2)D1(3a)',
  '7.3(2)N1(1)',
  '7.3(3)N1(1)',
  '8.0(1)',
  '8.1(1)',
  '8.1(2)',
  '8.1(2a)',
  '8.1(1a)',
  '8.1(1b)',
  '8.2(1)',
  '8.2(2)'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
