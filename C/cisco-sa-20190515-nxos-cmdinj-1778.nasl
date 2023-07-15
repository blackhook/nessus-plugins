#TRUSTED 36b8553bb28ac7d66dcab7ce5e968a525e5448268125ec55a38baff018c12f7ed50ff742774cf2f5f1aaf9855d231a01895d0e70a49c2cb6c234932501472c16cab6148bc93ae64845cd5aecae70a521aab4033f264bb68493a517461fd7811fe02cc80c83ae139d4b91a5e6ed4eaaf7090f5a4af358a5697b028a69c2cedea34227959057fbc3eea74d08c0d3622d45c46d991c69d6fe87ec2da617283361d3e698d2a0ec5a2e626b9bd5e244f13b1b03b5e57ab2085c00b613657fee318ca7b0660fa0fe65adc6fbc0abf732ba57bc7a5b17816762371b6df7ed4509dac56b02970d74572b54e87648b5d83c47285136a28e490adeb4ee2dc6138df895b3e3c1855a8da454003cf6ae39d1a7605f77bf12ea07daae7719673ef19d2d84ab13f39c33c14bd604b8acba9f37bcc9afa7357e679fd2dce95040283d32a878c25c9151c6dd851d6292e0ce3edb50a0ee5524312e5f42b5a7896a72dc82b7ad5584ca90478038799d89fc098f65b32f1f887600029b75704f8dcacf319fe0d8e3e7cab70e2d0c5b37a155562157d09c483244f14d81e485df2490e9cfcbdf48d130cf53ba44b32dce9215bc1cbc1f72fd24e2a9cbb35b3b61898a747f7a6c82be6f8255e8d5e8cf674e289c6778850ab09ba13e4bb92a09438ed0c4060964a41ebf3c4fa8ad60e7e444e2619fa977c843f8bb416d0c215360f749d2f3bba785b322
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128058);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-1778");
  script_bugtraq_id(108362);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh75996");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-cmdinj-1778");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco NX-OS Software Command Injection Vulnerability (CVE-2019-1778)");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is
affected by following vulnerability

  - A vulnerability in the CLI of Cisco NX-OS Software could
    allow an authenticated, local attacker to execute
    arbitrary commands on the underlying Linux operating
    system with the privilege level of root.The
    vulnerability is due to insufficient validation of
    arguments passed to a specific CLI command on the
    affected device. An attacker could exploit this
    vulnerability by including malicious input as the
    argument of an affected command. A successful exploit
    could allow the attacker to execute arbitrary commands
    on the underlying Linux operating system with elevated
    privileges. An attacker would need valid administrator
    credentials to exploit this vulnerability.
    (CVE-2019-1778)

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-cmdinj-1778
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee30c1df");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh75996");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvh75996");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1778");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

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

if (product_info.device == 'Nexus' && product_info.model !~ '^(3[056]|9[05])[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '7.0(3)I7(5a)',
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
  '7.0(3)I2(2)',
  '7.0(3)I2(1a)',
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
  '7.0(3)F3(3b)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3)',
  '7.0(3)F3(2)',
  '7.0(3)F3(1)',
  '7.0(3)F2(2)',
  '7.0(3)F2(1)',
  '7.0(3)F1(1)',
  '7.0(3)',
  '7.0(2)N1(1a)',
  '7.0(2)N1(1)',
  '7.0(2)I2(2c)',
  '7.0(1)N1(3)',
  '7.0(1)N1(1)',
  '7.0(0)N1(1)'
);
workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvh75996'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list, switch_only:TRUE);
