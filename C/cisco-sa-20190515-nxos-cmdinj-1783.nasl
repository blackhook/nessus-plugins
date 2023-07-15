#TRUSTED 034acbaa035ecf1e288803edca078ece92668caa2c173bb962d769c64f5e560e266723ae72fde332cef475eac08aa31466e80282386c4cc31f486a92c210dfcef19da8ded37dca4ac319b7ea6e18500cc37e5657cf324e67115bf80993c9c37996c897fe55b62044be20a710b10a6f9711790773a5e002be81d63da6dc988bc40d7b7a426e3598a8fe4b73b4b7388cfdcccac80438d48e6b95f8f7e97aa4516f4619b32e321b5bb9955b9e21c76e87d23fa2d8218320ecafcd2df789aa6879ad1139aac999eb85094a7d6d93d0bc33f110addf3aa1775e21156d11a9e3b421430f8602255299171bfd73ed453d8ea1a0745b4b459a57ee11776dbb7c17182a12b1e8094114ae3ce28c166818c88c207b2882965a456488bad3da96a33e13e2795b6d743e546793d0bcc1bfe9714a371c34999461b2281e5d7b5ed730f821c7ae6037f231d982c1a706a8aab813ceb267aae36f0827ea335c53244bc487a1ef3415142610a9b4a164f5cc53e3f33a6fd9e4ead8beabd3c64f15c682ca5f1859239ca331c11bb84084472ba0eb06f7f70de10b0717ca6686389ca01f9a8535a726c5c7c816493c366413f42125edb05e0838f66faa97ecae0464960a7fdd934c01059978b01baebe4641364f28ec0d421c105be03835f07c01ef5463a94791e2fa878c74771283cf7989ad72e65aa96976ddcd6c7e1fc20e3434424950ef48f3b7
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130975);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/25");

  script_cve_id("CVE-2019-1783");
  script_bugtraq_id(108370);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj03966");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi42281");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-cmdinj-1783");

  script_name(english:"Cisco NX-OS Software Command Injection (cisco-sa-20190515-nxos-cmdinj-1783)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a command injection vulnerability due to
insufficient validation of arguments passed to a specific CLI command on an affected device. An authenticated, local
attacker can exploit this to execute arbitrary commands on the underlying Linux operating system with root privileges.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-cmdinj-1783
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a2744ce");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi42281");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj03966");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi42281 and CSCvj03966");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1783");

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
    cbi = 'CSCvi42281';
  else if (product_info.model =~ '^(55|56|60)[0-9]{2}')
    cbi = 'CSCvj03966';
}

if (cbi == '')
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
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
  '7.3(3)N1(1)'
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
