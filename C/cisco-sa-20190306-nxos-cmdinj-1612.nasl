#TRUSTED 8385462f1e8116d8adfdd8ff6e4750e4e29bbc44be0dba1f526696c4f0b6c4eda36a9c8827417692129ef6b3c57f18da669ebe99aeedf9c97b5afb5b0e009cac66dc0169d7ee1c0ce1dd7a42f62c2e4ae2ef76eac174227cdacae26b81f5b172b46ddf92f2cdc7ccc5585edeaa0443f13c3cc467b17c8449f33557a3d3f3d7f4583f5e72e81b7fa57f84a6f9df05de3945e8281a4dd6db022ef46275078cfdb820a01681fd632a261237fd03d5c18254a1c8461991cd4f0e6d7059f45055a9bc8a88fddefb4f23ab942442f2da89e19bd2c909ce9cd971f5a3bac55eb917b059439d25591feba43de3d9f1d30bc3a6bd7c976be36e1722a07e2f3e7bc37649a4bdc6a5047273368f9b13429ddf29d423a3722b3e7b38dfb1d0085578e2e2c29ebb068a410944774645293a71bb35363131afab9227f237017febaf3f9e8f87f8095d82a7824dadaa1b4f699bbf8d31395c98d10e33f430d255f4b1726ae0baa77664b349c11b712d221fd69abcee0fdc05b70e15b1dba3987d8f7a4671693a154a4d009491b49b3d8c5b93e03968aad7f2d2e30529ed3e25007bcea9148c70699680319337a7b76d265e6f3b9a7505f1bd46302bf5c3757ac9f24d82c204a93eb6fe8f87ac427379d9d515c18d285bf575f9da050602859e5f29aea5b2c6bdb54576cf5d4d7ff9a21644c87e877d93d041bf715aa4ec7468cff3d7c7c408bbfb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132245);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id("CVE-2019-1612");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi42373");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxos-cmdinj-1612");

  script_name(english:"Cisco NX-OS Software CLI Command Injection Vulnerability (CVE-2019-1612)");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is
affected by following vulnerability

  - A vulnerability in the CLI of Cisco NX-OS Software could
    allow an authenticated, local attacker to execute
    arbitrary commands on the underlying operating system of
    an affected device.The vulnerability is due to
    insufficient validation of arguments passed to certain
    CLI commands. An attacker could exploit this
    vulnerability by including malicious input as the
    argument of an affected command. A successful exploit
    could allow the attacker to execute arbitrary commands
    on the underlying operating system with elevated
    privileges. An attacker would need valid administrator
    credentials to exploit this vulnerability.
    (CVE-2019-1612)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-cmdinj-1612
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fbf5635b");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi42373");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvi42373");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1612");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");

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

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

if ('Nexus' >!< product_info.device) audit(AUDIT_HOST_NOT, 'affected');
cbi = '';

if (product_info.model =~ '^(90|3[05])[0-9][0-9]')
  cbi = 'CSCvi42373';
else if (product_info.model =~ '^(95|36)[0-9][0-9]')
    cbi = 'CSCvj12009';
else audit(AUDIT_HOST_NOT, 'affected');

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
  '7.0(3)F3(3b)',
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
  '6.1(2)I3(3.78)',
  '6.1(2)I3(3)',
  '6.1(2)I3(2)',
  '6.1(2)I3(1)',
  '6.1(2)I2(2b)',
  '6.1(2)I2(2a)',
  '6.0(2)U6(9)',
  '6.0(2)U6(8)',
  '6.0(2)U6(7)',
  '6.0(2)U6(6)',
  '6.0(2)U6(5c)',
  '6.0(2)U6(5b)',
  '6.0(2)U6(5a)',
  '6.0(2)U6(5)',
  '6.0(2)U6(4a)',
  '6.0(2)U6(4)',
  '6.0(2)U6(3a)',
  '6.0(2)U6(3)',
  '6.0(2)U6(2a)',
  '6.0(2)U6(2)',
  '6.0(2)U6(1a)',
  '6.0(2)U6(10)',
  '6.0(2)U6(1)',
  '6.0(2)U5(4)',
  '6.0(2)U5(3)',
  '6.0(2)U5(2)',
  '6.0(2)U5(1)',
  '6.0(2)U4(4)',
  '6.0(2)U4(3)',
  '6.0(2)U4(2)',
  '6.0(2)U4(1)',
  '6.0(2)U3(9)',
  '6.0(2)U3(8)',
  '6.0(2)U3(7)',
  '6.0(2)U3(6)',
  '6.0(2)U3(5)',
  '6.0(2)U3(4)',
  '6.0(2)U3(3)',
  '6.0(2)U3(2)',
  '6.0(2)U3(1)',
  '6.0(2)U2(6)',
  '6.0(2)U2(5)',
  '6.0(2)U2(4)',
  '6.0(2)U2(3)',
  '6.0(2)U2(2)',
  '6.0(2)U2(1)',
  '6.0(2)U1(4)',
  '6.0(2)U1(3)',
  '6.0(2)U1(2)',
  '6.0(2)U1(1a)',
  '6.0(2)U1(1)',
  '5.0(3)U5(1j)',
  '5.0(3)U5(1i)',
  '5.0(3)U5(1h)',
  '5.0(3)U5(1g)',
  '5.0(3)U5(1f)',
  '5.0(3)U5(1e)',
  '5.0(3)U5(1d)',
  '5.0(3)U5(1c)',
  '5.0(3)U5(1b)',
  '5.0(3)U5(1a)',
  '5.0(3)U5(1)',
  '5.0(3)U4(1)',
  '5.0(3)U3(2b)',
  '5.0(3)U3(2a)',
  '5.0(3)U3(2)',
  '5.0(3)U3(1)',
  '5.0(3)U2(2d)',
  '5.0(3)U2(2c)',
  '5.0(3)U2(2b)',
  '5.0(3)U2(2a)',
  '5.0(3)U2(2)',
  '5.0(3)U2(1)',
  '5.0(3)U1(2a)',
  '5.0(3)U1(2)',
  '5.0(3)U1(1d)',
  '5.0(3)U1(1c)',
  '5.0(3)U1(1b)',
  '5.0(3)U1(1a)',
  '5.0(3)U1(1)'
);

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , cbi,
'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  switch_only:TRUE
);
