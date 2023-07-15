#TRUSTED ac1f28dfea124fbb969675294b10f096d7be76e9bba2b9055df264d3bf9cdbee071d8aa119769f0a64cdeb11e15eaa2cc37b6a71427bf31a77c71cd763b6095a89b40263797e21a83ea415eef2b10a5d9fafcabc0b543c681beb3430d33b89f894e469243f90aff3302758ab2bfea2cef6aa7781c868909d92ee302499963376d507be27b85952da6f0fe9969afe68119cae6c9cd6554bb0d5e443545e02029f32a234b5f9df2cecf4a8351074e7470690bc694d0ef04a4b51618207f0ca39b605213d77890b5a7d4d8f792007b54cc928e66aee338c72e4b847bf63f0362c82e07f654e55f3eac6ee050c3f821764f9462c8b24d6e300db7a9d3fe236021afb3bc0c1d84a984ad361f85f5318c29b76670fa249fd66006dcdd44b819005633b04ff63622a9bd6868f9ee013a5a33ede7848b90644fa9224b14f8897591658b2b639db7d526fa4f6b9ebde59cadb102bc2539f456fea4847a7457225db27fd8da91f3cbcc4c57f816b28c480474984f8b070cb21c0de23731657db45d10b6d2485054a43da6ccb4ee0f67b8b2d8e534997041e98504f3b758cd6f982f71110e5f74b6a95a70be9a3b79d7dca1b8922721495c29d784abf062b1aa66d49449a0313725cdd1ce2046e5b8ffd1f1bb9a77a96a6ec0299505321d7a905d6266a005f367d446a2003e8774206ed722f9f51891c941b01b0b2e7d865c3b8c5e802c69e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130974);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/25");

  script_cve_id("CVE-2019-1776");
  script_bugtraq_id(108377);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh20076");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh20081");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96429");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96431");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96432");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96433");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-cmdinj-1776");

  script_name(english:"Cisco NX-OS Software Command Injection (cisco-sa-20190515-nxos-cmdinj-1776)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a command injection vulnerability due to
insufficient validation of arguments passed to a specific CLI command on an affected device. An authenticated, local
attacker can exploit this to execute arbitrary commands on the underlying Linux operating system with root privileges.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-cmdinj-1776
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ebd996ed");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh20076");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh20081");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96429");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96431");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96432");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96433");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvh20076, CSCvh20081, CSCvi96429, CSCvi96431,
CSCvi96432, and CSCvi96433.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1776");

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
    cbi = 'CSCvh20081';
  else if (product_info.model =~ '^(30|35|90)[0-9]{2}')
    cbi = 'CSCvh20076, CSCvi96431';
  else if (product_info.model =~ '^36[0-9]{2}' || product_info.model =~ '^95[0-9]{2}R')
    cbi = 'CSCvi96429';
  else if (product_info.model =~ '^(55|56|60)[0-9]{2}')
    cbi = 'CSCvi96432';
}
else if ('MDS' >< product_info.device && product_info.model =~ '^90[0-9]{2}')
  cbi = 'CSCvh20081';
else if ('UCS' >< product_info.device && product_info.model =~ '^6[23][0-9]{2}')
  cbi = 'CSCvi96433';

if (cbi == '')
  audit(AUDIT_HOST_NOT, 'affected');

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
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
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
  '8.2(1)',
  '8.2(2)',
  '7.3(4)N1(1)'
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
