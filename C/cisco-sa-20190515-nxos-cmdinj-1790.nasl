#TRUSTED 8f882a38d632e37629e389ee3c1b794a3bfb207796621d4791c76e42560ceff2e6516d473ecb6bd39c3b553c14f1b95cd2675f09210a57140fcdd48abad937db7b19513044a20695d4e19208a2cfbb0d481eefda1d7f61a4d2222d57ed58fa38b12ec8c5600e9b77371abfb0fd5392cbcdeda7b1eef29fca88074a94e4fd29637ab0127487724537b47b54cc785cfe8ea2ad628c041529388bff88341a31a56cecdd45ccf1d12a0dbcd187fe53e0046bd87c42d0fb5dbcbc2509193ccc3f1156d523658c8df8a29df81e143ea54bf466d7a24e62a32988e55099eedd9faa27d5d3f14efbc8a686109939569b6a7652a71ef273239b58c4dfdd80595960141b97114e0e6a0a09dd03011016e8e5a20f8bd2be588b8301acb2f4279d6871d489a37aa6767a8f9d7dab9ef6284b301ce4b88d11c0829aa9172212b637058eea0364dfca3eab0ae16acfa445de1f85893792362d794238cdcc368fa0b32e01df160974899debe6637b48bbe897efb098ca9bb401d50ffdf710ad9920638853215423448c5d895e2bcd388af5268cf020a10df1cf4a0f7c5fa49d75f725ddecd7e4fcb32d541bfd0e269117e4af17baa26a38da90b1816cb865036d7cfddb14b9b4909b575b72195e37049d2604850e6047e4723a271ec27eeb021ceae8edc46535c0391a92cfdde94080d7db2c32c0ed680e42e85a8a57f04305759b658e8c19ca61
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130973);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/25");

  script_cve_id("CVE-2019-1790");
  script_bugtraq_id(108383);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh20096");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh20112");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96504");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96509");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96510");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-cmdinj-1790");

  script_name(english:"Cisco NX-OS Software Command Injection (cisco-sa-20190515-nxos-cmdinj-1790)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a command injection vulnerability due to
insufficient validation of arguments passed to certain CLI commands on an affected device. An authenticated, local
attacker can exploit this to execute arbitrary commands on the underlying operating system with elevated privileges.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-cmdinj-1790
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62ac8674");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh20096");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh20112");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96504");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96509");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96510");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvh20096, CSCvh20112, CSCvi96504, CSCvi96509,
and CSCvi96510.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1790");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/14");

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
    cbi = 'CSCvh20112';
  else if (product_info.model =~ '^(30|35|90)[0-9]{2}')
    cbi = 'CSCvh20096';
  else if (product_info.model =~ '^36[0-9]{2}' || product_info.model =~ '^95[0-9]{2}R')
    cbi = 'CSCvi96504';
  else if (product_info.model =~ '^(55|56|60)[0-9]{2}')
    cbi = 'CSCvi96509';
}
else if ('MDS' >< product_info.device && product_info.model =~ '^90[0-9]{2}')
  cbi = 'CSCvh20112';
else if ('UCS' >< product_info.device && product_info.model =~ '^6[23][0-9]{2}')
  cbi = 'CSCvi96510';

if (cbi == '')
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
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
  '7.0(3)I7(5a)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)I7(4)',
  '7.0(3)I7(5)',
  '7.0(3)I7(5a)',
  '8.2(1)',
  '8.2(2)'
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
