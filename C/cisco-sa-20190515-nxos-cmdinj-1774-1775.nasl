#TRUSTED 567f779988a9a1b991e3cbc6f31e44290e1522cfc53424f2187c55098e6111d16b4ec5ad2211572c26eb55575b0ea573cda2d85f5b63be53a34333b965a0912f9caf98f6bc2ff943beb6c47bbad1448b4a453516e60d49cc1b984e114e67e6870bcf37adf2d22b068a196c18946bae8d3fb1aba20662f5d9cf85ff90c5ef5a1956f414b03480f6ff35ab7b29b76fc7fa391f87dea2a7a557818532cbed7888ad090d64e3d7c83c81f748558aa906c40f8dfee20a8677042b2cc0c783856c22e20b3f5d73feafaef773ef878d93b4515879ed0385f7a4b6b9f134e0e17132494404887282887b41a1ecdcadd66eb37df48a7bb57cefac8867ad205b07f7ba8fe63e6073fd4162dc790d7afbb3af137dd0a9eab90f2cdd98b8c6c5388522723449097b1bc410cc7aa36bd7118f5be4761356a791cd5c6a70f0eb43d5659d14cfe14b7aef4957a697f23bdd035592927ca53478deaf0614621dbc95481141c5611bb2862493fed98205fe6efb5f4df68a26862c00b5efeaa215bc8475f30dda23a6ad1c46bcfaabe1e41f303c23079bf861d3a04df2f83f7398afad275062c0e13e6495dac5cfaf27679215d275faeeddfed0c627a9b15e467941e81ae3438d56f9d862296416ba048a3c47b4568a61351247da16766568c10a59ebae0d454d0804bb55c68d12ca9a2f6834a18304a90bbac4f352d3fd50a94e01bcf7792b7b36c6
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130916);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/25");

  script_cve_id("CVE-2019-1774", "CVE-2019-1775");
  script_bugtraq_id(108371);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh75895");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh75909");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh75968");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh75976");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi92256");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi92258");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi92260");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99195");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99197");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99198");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-cmdinj-1774-1775");

  script_name(english:"Cisco NX-OS Software Multiple Vulnerabilities (cisco-sa-20190515-nxos-cmdinj-1774-1775)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by two command injection vulnerabilities due
to insufficient validation of arguments passed to certain CLI commands. An authenticated, local attacker could exploit
these vulnerabilities to execute arbitrary commands on the underlying operating system with elevated privileges.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-cmdinj-1774-1775
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?217a964d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh75895");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh75909");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh75968");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh75976");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi92256");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi92258");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi92260");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99195");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99197");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99198");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvh75895, CSCvh75909, CSCvh75968, CSCvh75976,
CSCvi92256, CSCvi92258, CSCvi92260, CSCvi99195, CSCvi99197, and CSCvi99198.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1774");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/13");

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
if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^7[07][0-9]{2}')
    cbi = 'CSCvh75895, CSCvh75909';
  else if (product_info.model =~ '^(30|35|90)[0-9]{2}')
    cbi = 'CSCvh75968, CSCvh75976, CSCvi99197, CSCvi92258';
  else if (product_info.model =~ '^36[0-9]{2}' || product_info.model =~ '^95[0-9]{2}R')
    cbi = 'CSCvi99195, CSCvi92256';
  else if (product_info.model =~ '^(55|56|60)[0-9]{2}')
    cbi = 'CSCvi99198, CSCvi92260';
}
else if ('MDS' >< product_info.device && (product_info.model =~ '^90[0-9]{2}'))
  cbi = 'CSCvh75895, CSCvh75909';

if (cbi == '')
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
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
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(3b)',
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
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '8.1(1)',
  '8.1(1a)'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info.version,
  'bug_id'   , cbi,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
