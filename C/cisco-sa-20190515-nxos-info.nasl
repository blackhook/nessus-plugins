#TRUSTED 6ef0f2a48237ab318b63cdec1c4a35607029faf10cb6658d4e58c14a78405e30cdd4b2cbe22386fc07d1d0a2862d60162def456878de706fa36fcb8353fefe8d6dfa47d7bcabe985b27aa76ca0c24dbfee917111a8593354544f4de4e3977a7f2b0373b7cc6c68e531d659ee6ad331aa0b33ab6c35ccb00bc0d49d9f2e8dbf993ac71e077c43e0723027d8a010025dabcfb759f6257d00c5d220b536734c62cfd6932d4af4eb1128b9680071ac2330aafbeb73abb8339807b98bc07b337dd4613b179b5b525f9fd0026b13e8888000b5bee711a37a84011b31f06a899784245f7dee5290ca64e96c1367a9e34f8808095f90b8c775f91e7fab0766b00fae0955c90db3084273ce44495950870a20c2402465b2abc8dd934b017ec9a5e53914638962dc4770da58a122832976dda9832099567a4b0cab02c01fa5588974989a67537436015e6cb1308be95fbe31fdc15ba40191e4cc500b869de199aa429d5c0015c057ef2f7dfe07066957a765ec023c2a5e88d88a245e0ccad9bfacb65208a91f45a6f4bc1ece92ad01c0ce69d35ee7a5f690e161e6dc009a6c2c4e06c52da3bf61e8290381a84b037407a2fb7706454bca3ee818fd5ffb5d586cae5ca5c3dcff0b8afac3b8d06ff590c7cc524e7c1523b47776dc0f0c0ad0c3ab3032d16f67f420aab2ead5d61a281862526cfb6617cda05ef047d3ec3b0a017ea872b6771a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136482);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/19");

  script_cve_id("CVE-2019-1734");
  script_bugtraq_id(108381);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj59436");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj50808");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj50810");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj50814");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj50816");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj50836");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-fxos-info");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco NX-OS Software Sensitive File Read Information Disclosure Vulnerability (cisco-sa-20190515-nxos-fxos-info)");
  script_summary(english:"Checks the version of Cisco Nexus Operating System (NX-OS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Nexus
Operating System (NX-OS) is affected by following vulnerability

  - A vulnerability in the implementation of a CLI
    diagnostic command in Cisco FXOS Software and Cisco NX-
    OS Software could allow an authenticated, local attacker
    to view sensitive system files that should be
    restricted. The attacker could use this information to
    conduct additional reconnaissance attacks.The
    vulnerability is due to incomplete role-based access
    control (RBAC) verification. An attacker could exploit
    this vulnerability by authenticating to the device and
    issuing a specific CLI diagnostic command with crafted
    user-input parameters. An exploit could allow the
    attacker to perform an arbitrary read of a file on the
    device, and the file may contain sensitive information.
    The attacker needs valid device credentials to exploit
    this vulnerability. (CVE-2019-1734)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-fxos-info
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92f90474");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj59436");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj50808");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj50810");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj50814");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj50816");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj50836");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the appropriate Cisco bug ID:
  - CSCvj59436
  - CSCvj50808
  - CSCvj50810
  - CSCvj50814
  - CSCvj50816
  - CSCvj50836");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1734");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/12");

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

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

cbi = '';
if('MDS' >< product_info.device && product_info.model =~ '^9[0-9][0-9][0-9]')
  cbi = 'CSCvk50808';
else if ('UCS' >< product_info.device && product_info.model =~ '^6[23][0-9][0-9]')
  cbi = 'CSCvk50814';
else if('Nexus' >< product_info.device)
{
  if(product_info.model =~ '^(30[0-9][0-9]|90[0-9][0-9])')
    cbi = 'CSCvj59436';
  else if(product_info.model =~ '^(35[0-9][0-9])')
    cbi = 'CSCvj50810';
  else if (product_info.model =~ '^(5[56]|60)[0-9][0-9]')
    cbi = 'CSCvj59436';
  else if (product_info.model =~ '^7[07][0-9][0-9]')
    cbi = 'CSCvk50808';
  else if (product_info.model =~ '^(36)[0-9][0-9]')
    cbi = 'CSCvj50838';
  else audit(AUDIT_HOST_NOT, 'affected');
}

else audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
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
  '6.0(2)A8(10a)',
  '6.0(2)A8(10)',
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
  '7.0(3)',
  '7.0(0)N1(1)',
  '7.0(1)N1(1)',
  '7.0(1)N1(3)',
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
  '7.0(3)F3(3b)',
  '7.0(3)F3(5)',
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
  '7.0(3)I7(5a)',
  '7.0(3)I5(1)',
  '7.0(3)I5(2)',
  '7.0(3)I6(1)',
  '7.0(3)I6(2)',
  '7.0(3)I7(2)',
  '7.0(3)I7(5a)',
  '7.3(0.2)',
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
  '7.3(2)N1(0.296)',
  '7.3(2)N1(1)',
  '7.3(3)N1(1)',
  '8.3(1)'
);

reporting = make_array(
    'port'     , 0,
    'severity' , SECURITY_NOTE,
    'version'  , product_info['version'],
    'bug_id'   , cbi,
    'disable_caveat', TRUE
);


cisco::check_and_report(
    product_info:product_info, 
    reporting:reporting, 
    vuln_versions:version_list
);