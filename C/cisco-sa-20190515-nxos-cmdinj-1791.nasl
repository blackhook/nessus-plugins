#TRUSTED 003969232860bd8ba1f070b52a3d1cc55aa510be3713953e59195e9a149d5dcb93c532d591c8b05c1bd0e90c8cc822e025d62c77527ee74d5f46e398eb6750d3df8b4e1258be1fe0c3f2d9c92e24957a20c52ed195b2fc580c454b1f96a662925c30611089dcae9f024a3f37f19de8a68bab5b3172af2b97b645c460cbb5cdc3a7981169947d2a31b4118da91d0c3b469c847cabf4291c787f6c9c60665dc7fc8490c324376ec7f3d0d825a5771e483f148625797dacd15a4806d046849f87322c141dc6d656be7881e00f71b64c960030e4eaa8bf4126efd71f4719f8b6ecf91a2085ec82ade7ac161ea11737eea4c64afb153b239f5c004b56979770cf615812941c136addd0c910738b1175d3a2c7c4eea7e5d14eee58dc6919056050cdd1371f8444e6147f3eff101c0f51588f55c3308754236b64be9173d06be231713692482aa24147991dd85ebb11a37015131055bd393e706df09216d8f1175656a0af8aaca7b027a4ae8e76bb20294d391347b56eeab35362be6c3cf650d61905d473a647560f26d9b093a8954926be41269d24ba2bd29506b768a351e6f5dba1a7f3aef20d36a5e254c8eb372e9a721818b0a770d786c142ca47c832f30ff65c0efd1f8f9d0cb902b84009ff431037c61a69e66f44c0600304bc082a589502e2e3aef057b67af55f562c2ab493e0e031279424b06271a3b8106ff76c6884c322da
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128079);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-1791");
  script_bugtraq_id(108390);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj63270");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj63667");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj50873");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj50876");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj50889");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-cmdinj-1791");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco NX-OS Software Command Injection Vulnerability (CVE-2019-1791)");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by vulnerability in the CLI of Cisco NX-OS
Software which allow an authenticated, local attacker with administrator credentials to execute arbitrary commands
with elevated privileges on the underlying operating system of an affected device. The vulnerability is due to
insufficient validation of arguments passed to certain CLI commands. An attacker could exploit this vulnerability
by including malicious input as the argument of an affected command. A successful exploit could allow the attacker
to execute arbitrary commands on the underlying operating system with elevated privileges. An attacker would need
valid administrator credentials to exploit this vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-cmdinj-1791
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8cefff9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj63270");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj63667");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj50873");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj50876");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj50889");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvj63270, CSCvj63667, CSCvj50873, CSCvj50876,
and CSCvj50889");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1791");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/22");

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

if (
  (product_info.device == 'Nexus' && product_info.model !~ '^(3[056]|5[56]|60|7[07]|9[05])[0-9][0-9]') ||
  (product_info.device == 'MDS' && product_info.model !~ '^(90)[0-9][0-9]'))
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '8.2(2)',
  '8.2(1)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(5)',
  '7.0(3)I7(4)',
  '7.0(3)I7(3)',
  '7.0(3)I7(2)',
  '7.0(3)I7(1)',
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
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(3b)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3)',
  '7.0(3)F3(2)',
  '7.0(3)F3(1)',
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
  '6.2(21)',
  '6.2(20a)',
  '6.2(20)',
  '6.2(2)',
  '6.2(19)',
  '6.2(18)',
  '6.2(17)',
  '6.2(16)',
  '6.2(15)',
  '6.2(14b)',
  '6.2(14a)',
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
  '6.0(2)A8(9)',
  '6.0(2)A8(8)',
  '6.0(2)A8(7b)',
  '6.0(2)A8(7a)',
  '6.0(2)A8(7)',
  '6.0(2)A8(6)',
  '6.0(2)A8(5)',
  '6.0(2)A8(4a)',
  '6.0(2)A8(4)',
  '6.0(2)A8(3)',
  '6.0(2)A8(2)',
  '6.0(2)A8(10a)',
  '6.0(2)A8(10)',
  '6.0(2)A8(1)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj63270, CSCvj63667, CSCvj50873, CSCvj50876, and CSCvj50889'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  switch_only:TRUE
);
