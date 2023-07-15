#TRUSTED 65d88b4891c7bd1103e75f87b066161ae2b592fa607f148c8d565d1e8f5d626bcefb8c12187e7e3b28b5f4b3950fc6c26aeeeec96a8aac9391b6c6d018ae2460eec6fad15e4b1dac488a94b3ba01af41aa367f9933ed6ee835c58cffe1a6075653719d817e1142bbcdb19f3c4d89e21f641595f7e21a7da0bfaf3f7b91e0e6703fbf9705b63091e96a0e0de28e4262d12b621ca71d6936f997db052eb1b8115e78fb77da3c1e95fdaed4a8133c3daf4f3b6fe7079e4c4c16ddfadc684466a857d8ca9f5de7ff07a4b503aa7885360d8cef91b93f26312ed0f96903523a9df2c18d82989f1b42d9f8908c2cccee67d0c73e1255e69eb143610b51f0064abaf5bc093ee8f35070e9c0f66ae0698ce086a18fe9b2a62f83f68f29f1f92aa802f64d93ea0744596116e7008962a36e8de452ad73b5e7b307e1ad2445152a67f713af36ddb6fa1c792dcafa59f1887aa1ace4db4e2f6407fb4dd1fdd11b13bf2d25931deff40ce747e0decce89e0266f7538db60f4b74daf8ca3efcb1ee1f22b788f8033ffd7baeb53b3068859f9cf28fcced56761d3962634da15c75833584c17e0daf6ed00d557ef9def032d88d4b364286f8353f341334d0c4d962149c5816c06e34c097bbcb960e424912bfbf08b75557ed7980a84bea9c83f057764a2138c5700f4c46272b925425f2895d97d7f3c87247e88f50cf85ad2f68936e3b3af39a93
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132414);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id("CVE-2019-1609");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk51387");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxos-cmdinj-1609");

  script_name(english:"Cisco NX-OS Software CLI Command Injection Vulnerability (Cisco-Sa-20190306-Nxos-Cmdinj-1609)");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is
affected by following vulnerability

  - A vulnerability in the CLI of Cisco NX-OS Software could
    allow an authenticated, local attacker to execute
    arbitrary commands on the underlying operating system of
    an affected device.The vulnerability is due to
    insufficient validation of arguments passed to certain
    CLI commands. An attacker could exploit this
    vulnerability by including malicious input as the
    argument of an affected command. A successful exploit
    could allow the attacker to execute arbitrary commands
    on the underlying operating system with elevated
    privileges. An attacker would need valid administrator
    credentials to exploit this vulnerability.
    (CVE-2019-1609)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-cmdinj-1609
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d2b8c46");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk51387");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvk51387");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1609");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/27");

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

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

cbi = '';

switch (product_info)
{
  case product_info.device == 'MDS':
    if (product_info.model =~ "90[0-9][0-9]") cbi = "CSCvk51388";
    else audit(AUDIT_HOST_NOT, 'affected');
  break;
  case product_info.device != 'Nexus':
    audit(AUDIT_HOST_NOT, 'affected');
  break;
  case product_info.model =~ '^(3[05]|90)[0-9][0-9]':
	cbi = "CSCvj63253";
  break;
  case product_info.model =~ '^(70|77)[0-9][0-9]': #7000 and 7700 series
	cbi = "CSCvk51388";
  break;
  case product_info.model =~ '^(36|95)[0-9][0-9]': #9500 series
	cbi = "CSCvk51387";
  break;
  case default:
    audit(AUDIT_HOST_NOT, 'affected');
}

version_list=make_list(
  '8.3(1)',
  '8.2(2)',
  '8.2(1)',
  '8.1(2a)',
  '8.1(2)',
  '8.1(1a)',
  '8.1(1)',
  '8.0(1)',
  '7.3(2)D1(3a)',
  '7.3(2)D1(3)',
  '7.3(2)D1(2)',
  '7.3(2)D1(1)',
  '7.3(1)DY(1)',
  '7.3(1)D1(1)',
  '7.3(0)DY(1)',
  '7.3(0)DX(1)',
  '7.3(0)D1(1)',
  '7.2(2)D1(2)',
  '7.2(2)D1(1)',
  '7.2(1)D1(1)',
  '7.2(0)D1(1)',
  '7.0(3)IX1(2a)',
  '7.0(3)IX1(2)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(5)',
  '7.0(3)I7(4)',
  '7.0(3)I7(3)',
  '7.0(3)I7(2)',
  '7.0(3)I7(1)',
  '7.0(3)I6(2)',
  '7.0(3)I6(1)',
  '7.0(3)I5(2)',
  '7.0(3)I5(1)',
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
  '7.0(3)F3(3a)',
  '7.0(3)F3(3)',
  '7.0(3)F3(2)',
  '7.0(3)F3(1)',
  '7.0(3)F2(2)',
  '7.0(3)F2(1)',
  '7.0(3)F1(1)',
  '7.0(2)I2(2c)',
  '6.2(9c)',
  '6.2(9b)',
  '6.2(9a)',
  '6.2(9)',
  '6.2(8b)',
  '6.2(8a)',
  '6.2(8)',
  '6.2(7)',
  '6.2(6b)',
  '6.2(6a)',
  '6.2(6)',
  '6.2(5b)',
  '6.2(5a)',
  '6.2(5)',
  '6.2(3)',
  '6.2(2a)',
  '6.2(25)',
  '6.2(23)',
  '6.2(21)',
  '6.2(20a)',
  '6.2(20)',
  '6.2(2)',
  '6.2(19)',
  '6.2(18)',
  '6.2(17)',
  '6.2(16)',
  '6.2(15)',
  '6.2(14)',
  '6.2(13b)',
  '6.2(13a)',
  '6.2(13)',
  '6.2(12)',
  '6.2(11e)',
  '6.2(11d)',
  '6.2(11c)',
  '6.2(11b)',
  '6.2(11)',
  '6.2(10)',
  '6.2(1)',
  '6.1(5a)',
  '6.1(5)',
  '6.1(4a)',
  '6.1(4)',
  '6.1(3)',
  '6.1(2)I3(5b)',
  '6.1(2)I3(5a)',
  '6.1(2)I3(5)',
  '6.1(2)I3(4e)',
  '6.1(2)I3(4d)',
  '6.1(2)I3(4c)',
  '6.1(2)I3(4b)',
  '6.1(2)I3(4a)',
  '6.1(2)I3(4)',
  '6.1(2)I3(3a)',
  '6.1(2)I3(3)',
  '6.1(2)I3(2)',
  '6.1(2)I3(1)',
  '6.1(2)I2(3)',
  '6.1(2)I2(2b)',
  '6.1(2)I2(2a)',
  '6.1(2)I2(2)',
  '6.1(2)I2(1)',
  '6.1(2)I1(3)',
  '6.1(2)I1(1)',
  '6.1(2)',
  '6.1(1)',
  '6.0(4)',
  '6.0(3)',
  '6.0(2)U6(9)',
  '6.0(2)U6(8)',
  '6.0(2)U6(7)',
  '6.0(2)U6(6)',
  '6.0(2)U6(5c)',
  '6.0(2)U6(5b)',
  '6.0(2)U6(5a)',
  '6.0(2)U6(5)',
  '6.0(2)U6(4a)',
  '6.0(2)U6(4)',
  '6.0(2)U6(3a)',
  '6.0(2)U6(3)',
  '6.0(2)U6(2a)',
  '6.0(2)U6(2)',
  '6.0(2)U6(1a)',
  '6.0(2)U6(10)',
  '6.0(2)U6(1)',
  '6.0(2)U5(4)',
  '6.0(2)U5(3)',
  '6.0(2)U5(2)',
  '6.0(2)U5(1)',
  '6.0(2)U4(4)',
  '6.0(2)U4(3)',
  '6.0(2)U4(2)',
  '6.0(2)U4(1)',
  '6.0(2)U3(9)',
  '6.0(2)U3(8)',
  '6.0(2)U3(7)',
  '6.0(2)U3(6)',
  '6.0(2)U3(5)',
  '6.0(2)U3(4)',
  '6.0(2)U3(3)',
  '6.0(2)U3(2)',
  '6.0(2)U3(1)',
  '6.0(2)U2(6)',
  '6.0(2)U2(5)',
  '6.0(2)U2(4)',
  '6.0(2)U2(3)',
  '6.0(2)U2(2)',
  '6.0(2)U2(1)',
  '6.0(2)U1(4)',
  '6.0(2)U1(3)',
  '6.0(2)U1(2)',
  '6.0(2)U1(1a)',
  '6.0(2)U1(1)',
  '6.0(2)',
  '6.0(1)',
  '5.2(9a)',
  '5.2(9)',
  '5.2(8i)',
  '5.2(8h)',
  '5.2(8g)',
  '5.2(8f)',
  '5.2(8e)',
  '5.2(8d)',
  '5.2(8c)',
  '5.2(8b)',
  '5.2(8a)',
  '5.2(8)',
  '5.2(7)',
  '5.2(6b)',
  '5.2(6a)',
  '5.2(6)',
  '5.2(5)',
  '5.2(4)',
  '5.2(3a)',
  '5.2(3)',
  '5.2(2s)',
  '5.2(2d)',
  '5.2(2a)',
  '5.2(2)',
  '5.2(1)',
  '5.1(6)',
  '5.1(5)',
  '5.1(4)',
  '5.1(3)',
  '5.1(1a)',
  '5.1(1)',
  '5.0(8a)',
  '5.0(8)',
  '5.0(7)',
  '5.0(5)',
  '5.0(4d)',
  '5.0(4c)',
  '5.0(4b)',
  '5.0(4)',
  '5.0(3)U5(1j)',
  '5.0(3)U5(1i)',
  '5.0(3)U5(1h)',
  '5.0(3)U5(1g)',
  '5.0(3)U5(1f)',
  '5.0(3)U5(1e)',
  '5.0(3)U5(1d)',
  '5.0(3)U5(1c)',
  '5.0(3)U5(1b)',
  '5.0(3)U5(1a)',
  '5.0(3)U5(1)',
  '5.0(3)U4(1)',
  '5.0(3)U3(2b)',
  '5.0(3)U3(2a)',
  '5.0(3)U3(2)',
  '5.0(3)U3(1)',
  '5.0(3)U2(2d)',
  '5.0(3)U2(2c)',
  '5.0(3)U2(2b)',
  '5.0(3)U2(2a)',
  '5.0(3)U2(2)',
  '5.0(3)U2(1)',
  '5.0(3)U1(2a)',
  '5.0(3)U1(2)',
  '5.0(3)U1(1d)',
  '5.0(3)U1(1c)',
  '5.0(3)U1(1b)',
  '5.0(3)U1(1a)',
  '5.0(3)U1(1)',
  '5.0(3)',
  '5.0(2a)',
  '5.0(2)',
  '5.0(1b)',
  '5.0(1a)',
  '4.2(8)',
  '4.2(6)',
  '4.2(4)',
  '4.2(3)',
  '4.2(2a)',
  '4.1(5)',
  '4.1(4)',
  '4.1(3)',
  '4.1(2)'
);

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , cbi,
'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  switch_only:TRUE
);
