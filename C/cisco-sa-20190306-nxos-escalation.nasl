#TRUSTED 2b40b8c52449bde1fd49634507221795d71e223be74b10f3c1a67975f8eb4bb08cff3f3bcc74111edc710ccee7fd44c61727d3269b33fa5131ca7e5957d8dc37ec357c536f76d264da31573d99cbc60a22eaac9d6e34e42f77adbd221f6922b3f63df9e83d4a3f9c02faaba52f8ff095cf47efa75a10d8f6625d6c07c2993011dbf2fadbd1ded0b4762d57064dc730d8c475f6d3573f9c0f1cf1a8f72fb9ae00c2308139f691d471053506011f3a524b3a1acf937ebad26387f6f5a81f6d43da92b83817d6090045ec8edb6e8c869a1cf5e6ea2a138add60c09c5e625cda45d79f3b10bfa0d82ced525b826cfe42e128998f613db7b0b9d7be354ddbbc85c9479fe2e2ee029b44fbf788085c6b715eb90f609be5292cc0735cfed735c6d0ca7d4ae08c038a25205c90f5359f223022cebd6e4c77676d3fd23b9e62a34677253a873f5da2b723f5b9f310677c9dbb7c64017553a75fd65ccedda30c641e4bfd15d4a55469c4b655dd89701530790d0786abc7a5224a999b6f7f9b0e231e114a21749f1369039b57423cd420d223a8240aba4759f274dbd239431d81181622c4120a35b17934224878a12d6cfa7fc3345edb13c0c09f67f4d8ee81a840f48cb5b3d6a8e3c3ad4bbb9702f48f8aa4b2e1ae93e55cc7e8cbf9e6e4ce68cc29b4bb784558b443c86e2cb60e01c53c91a1e279e02116672cbed188ef88e938030d87c9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132246);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id("CVE-2019-1602");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk70659");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxos-escalation");

  script_name(english:"Cisco NX-OS Software Privilege Escalation Vulnerability");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is
affected by following vulnerability

  - A vulnerability in the filesystem permissions of Cisco
    NX-OS Software could allow an authenticated, local
    attacker to access sensitive data that could be used to
    elevate their privileges to administrator.The
    vulnerability is due to improper implementation of
    filesystem permissions. An attacker could exploit this
    vulnerability by logging in to the CLI of an affected
    device, accessing a specific file, and leveraging this
    information to authenticate to the NX-API server. A
    successful exploit could allow an attacker to make
    configuration changes as administrator.Note: NX-API is
    disabled by default. (CVE-2019-1602)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-escalation
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f435018");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk70659");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvk70659");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1602");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

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

cbi = '';
if (product_info.device == 'Nexus' && product_info.model =~ '^3[05][0-9][0-9]')
  cbi = 'CSCvj59009';
else if (product_info.device == 'Nexus' && product_info.model =~ '^(95|36)[0-9][0-9]')
  cbi = 'CSCvk70659';
else if (product_info.device == 'Nexus' && product_info.model =~ '^(90)[0-9][0-9]')
  cbi = 'CSCvj59009';
else audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '7.0(3)I7(3)',
  '7.0(3)I7(2)',
  '7.0(3)I7(1)',
  '7.0(3)I6(2)',
  '7.0(3)I6(1)',
  '7.0(3)I5(2)',
  '7.0(3)I5(1)',
  '7.0(3)F3(4)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3)',
  '7.0(3)F3(2)',
  '7.0(3)F3(1)'
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
