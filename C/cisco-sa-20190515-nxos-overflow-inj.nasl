#TRUSTED 4ab057b4c23fc8a6864ae9e9724620e150fcfcd3948ed4be7f4f01a199215a9f0985749e83a730eeb7eeb704955d9c0be84ab44593c06685fda273f9410696c8d11f1546b1b2477ffd0e4346d1465a4b1c525d6b0f4529fca1da3750aeb39f47b45c1277e738aa2dc9f736080777053e89527427103b3ae640c64859bbce06c23579dfb59138f7ac3fb81262981344e1ce9ebe29839c621f90a881cfd0375510c28e35275673ade749246360f3316c045c77851f2e9e1db017224f53e45a91d710b9e3d41204254e65c1b67d37d040eb44b228e96f526936df3b827039881aa14319197bbbab07cbc931a26c97bdfb3b8411958dfd3b9d40c0ace907b3a62bff2877db9ad01eb186d25788009ab171c57c1c5be94e263a0885bfea5670554a4771467b83d123c0d55e1e05ac22f092626eb572710428b506bbc1fc69e8af1d04a87a8fc312d5c741d22dc868ac3b920e549d5222caf6da60b4136a43d8691cae019a81b11474729efd350b766172adad37820a377c28b9274ce2fa94a7c6524610d3436aac030f900d7ba00694b86cf536bf9febd742bf63b8330a8ab16fc51fbc7598996ecad738789ea29abeb0d941eb08e73d873e002d8f65962be8213edabdb70b3396eae28587c20146bbfd61840356fc96b28bc62b8bf4bfe0f623ac2731fe2ddd71787747c424e67810384411d5766e891e47d822c49afa7f650ea754
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126342);
  script_version("1.7");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-1767", "CVE-2019-1768");
  script_bugtraq_id(108386);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh76132");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh76129");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj00497");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj10162");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-overflow-inj");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco NX-OS Software Buffer Overflow and Command Injection Vulnerabilities");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is
affected by a vulnerability in the implementation of a specific CLI
command for Cisco NX-OS Software could allow an authenticated, local
attacker with administrator credentials to cause a buffer overflow
condition  or perform command injection. This could allow the
attacker to execute arbitrary commands with elevated privileges
on the underlying operating system of an affected device. The
vulnerability is due to insufficient validation of arguments
passed to a certain CLI command. An attacker could exploit this
vulnerability by including malicious input as the argument of
the affected CLI command. A successful exploit could allow
the attacker to execute arbitrary commands on the underlying
operating system with root privileges. An attacker would need
valid administrator credentials to exploit this vulnerability.
(CVE-2019-1767) (CVE-2019-1768)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-overflow-inj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4f90baf");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh76132");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh76129");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj00497");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj10162");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCvh76132, CSCvh76129, CSCvj00497, CSCvj10162");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1767");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77, 119);


  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/28");

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
bugIDs = NULL;

if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^3[05][0-9][0-9]' || product_info.model =~ '^90[0-9][0-9]') bugIDs = 'CSCvh76132, CSCvh76129';
  else if (product_info.model =~ '^36[0-9][0-9]' || product_info.model =~ '^95[0-9][0-9]') bugIDs = 'CSCvj00497, CSCvj10162';
}

if (isnull(bugIDs)) audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '7.0',
  '7.0(0)N1',
  '7.0(0)N1(1)',
  '7.0(1)N1',
  '7.0(1)N1(1)',
  '7.0(1)N1(3)',
  '7.0(2)I2',
  '7.0(2)I2(2c)',
  '7.0(2)N1',
  '7.0(2)N1(1)',
  '7.0(2)N1(1a)',
  '7.0(3)',
  '7.0(3)F1',
  '7.0(3)F1(1)',
  '7.0(3)F2',
  '7.0(3)F2(1)',
  '7.0(3)F2(2)',
  '7.0(3)F3',
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3b)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(4)',
  '7.0(3)I1',
  '7.0(3)I1(1)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(2)',
  '7.0(3)I1(3)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3b)',
  '7.0(3)I2',
  '7.0(3)I2(1)',
  '7.0(3)I2(1a)',
  '7.0(3)I2(2)',
  '7.0(3)I2(2a)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(3)',
  '7.0(3)I2(4)',
  '7.0(3)I2(5)',
  '7.0(3)I3',
  '7.0(3)I3(1)',
  '7.0(3)I4',
  '7.0(3)I4(1)',
  '7.0(3)I4(2)',
  '7.0(3)I4(3)',
  '7.0(3)I4(4)',
  '7.0(3)I4(5)',
  '7.0(3)I4(6)',
  '7.0(3)I4(7)',
  '7.0(3)I5',
  '7.0(3)I5(1)',
  '7.0(3)I5(2)',
  '7.0(3)I6',
  '7.0(3)I6(1)',
  '7.0(3)I6(2)',
  '7.0(3)I7',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , bugIDs
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
