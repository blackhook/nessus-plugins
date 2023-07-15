#TRUSTED a193c7bb9161e8533927a5011f4079846e65a5d72b2e32f8dc3d7f7ce21f052c406e16018a730d495f45245df473f2a3c5686a4e6d467b93f50c9e1ee24edf52c75dff43454f009961d26b0e1f30cf6a5efa94d845ed675a95edb1a50189d3e5e6feaf236635d957f5adc28d38d954ba92a82e0a8a3d625949b3d925f785b7dad361afedac4afeb4c270e502b87047f708ad75b02b9ebc2ef43b70c20c3ff6263fc6b14bc32ae5648767488ea0dea7e6fca9d973465c1c61d5837a2ef3d4b23cabe0c1d91f1a0e75dbac1d34304ff55464e7c7832adea97d6e0113ac527b4bbc0b0715a3ef2bbd04bb4ff6762ceb834013ffec36c4cff94c636854453d074a7b2de3e40d8599bf7509237b8d22a6eef75cc0cdf5b8178e2a09ec734b0116f208df050ad558f94b0e1862b69185b5fc9cfaeb26a58a122f91719ac59a3223be1ac432f5258467aa4360764f8a4105adcb80ee937bebf40b44647c37bce5c25df3fef7fad0f2ba47ea2b0450d535fe7c80c9531856b7a8c7e438030e36609127a12a1aa5cc316125874892a295bf2c20271988ecd3d8b0dbf70011cda8642e0dd5b89ddef395f53ba35a9784d0b68371859d8ff94e811eab976b8caac6a500d320dc92b2fc61ebf5eedd62c55aa2017facca85f2895407d5d56817fe694908d2a1af7cd22d5b5113525a7d43d5df8598d09e0903e1d7f1e8bf46d3c47553a943ae
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132342);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id("CVE-2019-1608");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi01422");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxos-cmdinj-1608");

  script_name(english:"Cisco NX-OS Software CLI Command Injection Vulnerability (cisco-sa-20190306-nxos-cmdinj-1608)");
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
    (CVE-2019-1608)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-cmdinj-1608
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01a1c104");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi01422");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvi01422");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1608");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/20");

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

cbi = '';
if ((product_info.device == 'Nexus' && product_info.model =~ '^7[70][0-9][0-9]')||(product_info.device == 'MDS' && product_info.model =~ '^90[0-9][0-9]'))
  cbi = 'CSCvi01422';
else audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '8.2(2)',
  '8.2(1)',
  '8.1(2a)',
  '8.1(2)',
  '8.1(1a)',
  '8.1(1)',
  '8.0(1)',
  '7.3(2)D1(3a)',
  '7.3(2)D1(3)',
  '7.3(2)D1(2)',
  '7.3(2)D1(1)',
  '7.3(1)DY(1)',
  '7.3(1)D1(1)',
  '7.3(0)DY(1)',
  '7.3(0)DX(1)',
  '7.3(0)D1(1)',
  '7.2(2)D1(2)',
  '7.2(2)D1(1)',
  '7.2(1)D1(1)',
  '7.2(0)D1(1)',
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
  '6.2(25)',
  '6.2(23)',
  '6.2(21)',
  '6.2(20a)',
  '6.2(20)',
  '6.2(2)',
  '6.2(19)',
  '6.2(18)',
  '6.2(17)',
  '6.2(16)',
  '6.2(15)',
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
  '6.1(5a)',
  '6.1(5)',
  '6.1(4a)',
  '6.1(4)',
  '6.1(3)',
  '6.1(2)',
  '6.1(1)',
  '6.0(4)',
  '6.0(3)',
  '6.0(2)',
  '6.0(1)',
  '5.2(9a)',
  '5.2(9)',
  '5.2(8i)',
  '5.2(8h)',
  '5.2(8g)',
  '5.2(8f)',
  '5.2(8e)',
  '5.2(8d)',
  '5.2(8c)',
  '5.2(8b)',
  '5.2(8a)',
  '5.2(8)',
  '5.2(7)',
  '5.2(6b)',
  '5.2(6a)',
  '5.2(6)',
  '5.2(5)',
  '5.2(4)',
  '5.2(3a)',
  '5.2(3)',
  '5.2(2s)',
  '5.2(2d)',
  '5.2(2a)',
  '5.2(2)',
  '5.2(1)',
  '5.1(6)',
  '5.1(5)',
  '5.1(4)',
  '5.1(3)',
  '5.1(1a)',
  '5.1(1)',
  '5.0(8a)',
  '5.0(8)',
  '5.0(7)',
  '5.0(5)',
  '5.0(4d)',
  '5.0(4c)',
  '5.0(4b)',
  '5.0(4)',
  '5.0(3)',
  '5.0(2a)',
  '5.0(2)',
  '5.0(1b)',
  '5.0(1a)',
  '4.2(8)',
  '4.2(6)',
  '4.2(4)',
  '4.2(3)',
  '4.2(2a)',
  '4.1(5)',
  '4.1(4)',
  '4.1(3)',
  '4.1(2)'
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
