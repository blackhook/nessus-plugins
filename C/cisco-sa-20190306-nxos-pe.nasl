#TRUSTED 21a9d521b1dbe9246659efcbe779ebe7b763e5a3b95019395f529ffa6d7909c3889272bd27db5c9f994676d23a842911ec3b840d4a77110e2ee1e3744aa1227469180aea39c0bfc0f2ee954296f3e557b686bd6dc6dbdb8cc3fa6cde4714e11eda9bde59fa04179b98a77c1e69f57df9ee56bcd8bf4f8fb336a835de1da0c3ea5a7281a1f4a77fff792b8a1432d8bc12e95f7377509f355f7047e3194b72f680c14247112139eaebd2b6902a60810b393656eed29a6d2d06ad59f5ae910caf147b65cc90b2621316e02b415e4c3fc670e2a0f954c8a3a1ff10a45a043c07bc6c11a9107caa15bbda52ce2d597814d41307dcdfdd71577284d2186f19156cb4d7ecf54ddb5426d1c793efa0b5842209f6610848c8ff34cd6482f8c9928f78903932ac544005d51adb3430e8ec76736f4f2fae9e90f410775b3124810413c6a7506f7443e513905301eb52f3d8d8a4c5dc43fbc3cbe5c59e24cf5bdaea6e28732c3c125039b217e49d59535c898f83a44e0f50c01e93a3b98b7388014c5a92997ac4be4d18a2e8995924ca51bbfcca8dcad5d4ca63abadb4b4ac5978f0926379fa60c1a3662187075cf31800d2ed353db183531faf27090ee473aae23f59dbb122145244ad6799aa288c42cad8307af14d2fcd860826dd81af2e9acee21a35fd403cf104ab39c03d68923d712e2dc1a7cbf771618468a1918195efb7660e759316
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127110);
  script_version("1.5");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-1596");
  script_bugtraq_id(107340);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj58962");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk71078");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxos-pe");

  script_name(english:"Cisco NX-OS Software Bash Shell Privilege Escalation Vulnerability");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability in the Bash shell
implementation for Cisco NX-OS Software could allow an authenticated, local attacker to escalate their privilege level
to root. The attacker must authenticate with valid user credentials. The vulnerability is due to incorrect permissions
of a system executable. An attacker could exploit this vulnerability by authenticating to the device and entering a
crafted command at the Bash prompt. A successful exploit could allow the attacker to escalate their privilege level to
root. (CVE-2019-1596)

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-pe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e5e4b66");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj58962");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk71078");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvj58962, and CSCvk71078");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1596");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
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
if (product_info.device == 'Nexus' && product_info.model =~ '^(3[05]|90)[0-9][0-9]')
  cbi = 'CSCvj58962';
else if (product_info.device == 'Nexus' && product_info.model =~ '^(36|95)[0-9][0-9]')
  cbi = 'CSCvk71078';
else
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
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
  '7.0(3)F3(3a)',
  '7.0(3)F3(3)',
  '7.0(3)F3(2)',
  '7.0(3)F3(1)',
  '7.0(3)F2(2)',
  '7.0(3)F2(1)',
  '7.0(3)F1(1)',
  '7.0(2)I2(2c)',
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
  '6.1(2)I1(2)',
  '6.1(2)I1(1)',
  '6.1(2)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
