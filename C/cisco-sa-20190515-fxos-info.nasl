#TRUSTED 909b1c51ca79bcd19e15ccb3950dd03eb7d3e57cb9f7b05f2fbcd1025c7cdc6713346240d29652aeb3dc9e07f8a8a15230e7422eea2f01f45b40cae133be608f87760d52ca9b80fb0e8a52d4b8a38c87c38a0bba37f9180f515b2485b8e5e258f667d8b86b07eb3052b278c45bc3d4cac79c34e2fdf5787329d61a3ec24e4417ad893e84fd4f0dec6285c4626a75e07e36eb917cf0bf6a75d0f5c72af84ae59469c95d606a3e992dbb9eff97fc7f1308ecc30235fa195da7230c7090b2d4db3ba59a8af1434e733eab79e4291183566204a9ad0c168833075807c970dd612ca239c2ffeeedaf4fc35762c849f1ec0fd6b11e2f6674ba7ac2f866cc74d58dfb74ad52a135ef24e7f2ff0dd37e2409db90a55c4d4bcae6be667686a63017472ee694e690e70546d42328c23450b5f874cef8af49a9be97e63732f8b35859c1f7489cdd78da3219ef86719ee6b49bcc54f7df4e0836a9b95ffa57c97fe193c9dc854253c45b8f03eb74b87d7a4e4edddfb167c7cc1d1b73fb9c841d0949e9f9850f31f9f5da28fc0384485893193dfcd4fa2bf60cf2fb3b466471300f67aa4f7bc0f7076da1466da7878e7a4522955ebb9ee125805b107678142af0c1a407335d7484481d5df7ae7e871d0156f27de8ccf7cd6f50c7d18f6159ec4684bc9357bc86ae50cb4ab289f6eb9929284718a05eef83ee9a670a58b3bf8fe3273e6b8e3618
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136481);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/13");

  script_cve_id("CVE-2019-1734");
  script_bugtraq_id(108381);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj59436");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj50808");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj50810");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj50814");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj50816");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj50836");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-fxos-info");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco NX-OS Software Sensitive File Read Information Disclosure Vulnerability (cisco-sa-20190515-nxos-fxos-info)");
  script_summary(english:"Checks the version of Cisco Firepower Extensible Operating System (FXOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Extensible
Operating System (FXOS) is affected by following vulnerability

  - A vulnerability in the implementation of a CLI
    diagnostic command in Cisco FXOS Software and Cisco NX-
    OS Software could allow an authenticated, local attacker
    to view sensitive system files that should be
    restricted. The attacker could use this information to
    conduct additional reconnaissance attacks.The
    vulnerability is due to incomplete role-based access
    control (RBAC) verification. An attacker could exploit
    this vulnerability by authenticating to the device and
    issuing a specific CLI diagnostic command with crafted
    user-input parameters. An exploit could allow the
    attacker to perform an arbitrary read of a file on the
    device, and the file may contain sensitive information.
    The attacker needs valid device credentials to exploit
    this vulnerability. (CVE-2019-1734)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-fxos-info
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92f90474");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj59436");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj50808");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj50810");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj50814");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj50816");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj50836");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the appropriate Cisco bug ID:
  - CSCvj59436
  - CSCvj50808
  - CSCvj50810
  - CSCvj50814
  - CSCvj50816
  - CSCvj50836");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1734");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_extensible_operating_system_(fxos)");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'FXOS');
product_info['model'] = product_info['Model'];

if(
  isnull(product_info['model']) ||
  product_info['model'] !~ "^(41|93)[0-9]{2}$"
)
  audit(AUDIT_HOST_NOT, 'affected');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '2.2.2.91'},
  {'min_ver' : '2.3',  'fix_ver': '2.3.1.111'},
  {'min_ver' : '2.4',  'fix_ver': '2.4.1.101'}
];


reporting = make_array(
    'port'     , 0,
    'severity' , SECURITY_NOTE,
    'version'  , product_info['version'],
    'bug_id'   , 'CSCvk50816',
    'disable_caveat', TRUE
);

cisco::check_and_report(
    product_info:product_info, 
    reporting:reporting, 
    vuln_ranges:vuln_ranges
);