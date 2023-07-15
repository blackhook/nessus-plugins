#TRUSTED 47e912264759829c03c64b3aad86cdb87117ab1a600a17431b2aeaf8034261b446100bb112d5cf4a2d49ec68a19600652828232b815106e2347cb7973ab6bcc10e056834894494b55b01e982c20bebfee87e36a30d607ccc54cc61dbe00817508c4c64fbaf56be50cc5d661a9f2aff486ee03d726f7ad665d35d2f2e167c4c2b93fc58911f1069397a8c663cc8d705b75db1ad773caee997abcd6b889a8edfeb66cedb7411d29caf32bfb6e2122c373c5f475b8c8c0b3e6991759d594c6634a037928ef8b36211b7b462b08174de39ea495e1c63c502564ed066505a4471a507d34a5317841ec29e9f0ee7805e0fc0081e20f4af60e94ed52cf5507c16025adcf1b445e628652018789694224636c92008b4a1c685e615d7f77a31176ea3dfac9459ac83cc3788ae435fd69bd74541c7432c56fc51ea5bcbd3d840880ef0fa73c3218fa04be1e865e147041028d810e922e64d14a085eb4f23064f1793b081cb5290fd4f20bd7b791b0db008a670132272d0e88054d1aa90112b13c1cd15339c1118d7ecc7a6ecc04abfcd923ffbcbcf8b7b9714a6a22e432c8013d5c9112fc0ba8d57f9960c0adac9be042a869cff6f994cc734829866674cebb65746dfdf16b4721c01fe933951c296b02b762b9c29418f09094c0bebfde2507b7aefe417ca7ba9593511fc0bd2257df45df46b1712de2bd5cc1a51712d655ec08eb56ffc36
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132679);
  script_version("1.4");
  script_cvs_date("Date: 2020/01/09");

  script_cve_id("CVE-2019-1769");
  script_bugtraq_id(108393);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh20032");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj00299");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-linecardinj-1769");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco NX-OS Software Line Card Command Injection (cisco-sa-20190515-nxos-linecardinj-1769)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a command injection vulnerability in the
CLI due to insufficient validation of arguments passed to a specific CLI command on the affected device. An
authenticated, local attacker with administrator credentials can exploit this, by including malicious input as the
argument of an affected command, in order to execute arbitrary commands on the underlying Linux operating system of an
attached line card with root privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-linecardinj-1769
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d873a6c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh20032");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj00299");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvh20032 and CSCvj00299.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1769");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/07");

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

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device)
  audit(AUDIT_HOST_NOT, 'affected');
# 9000 switches are affected only in standalone NX-OS mode, however ACI mode versions are formatted differently than the
# versions in this list, so we will not incorrectly flag any of these
if (product_info.model =~ '^(3[05]|90)[0-9][0-9]')
  cbi = 'CSCvh20032';
else if (product_info.model =~ '^(36|95)[0-9][0-9]')
  cbi = 'CSCvj00299';
else audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
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
  '7.0(3)I7(5a)',
  '7.0(3)I5(1)',
  '7.0(3)I5(2)',
  '7.0(3)I6(1)',
  '7.0(3)I6(2)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info.version,
  'bug_id'   , cbi
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
