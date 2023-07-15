#TRUSTED 929772f2b2649cbbbce05b5f6a048237cbc65788f972e4d782c5b8c3541374d8284785d8a7d1c8aba9d79a860fe8c0337e152d6b1aed463663b5a095d699621f6710596ffdb8407f182ee2f80d3e8d34a7caadcf354b1dd8879de6a02a6ac8e00f8c980eb7e98c28bca7f0aceff12f0af22339c60e0152e1671b273126669b2c123b4d94097cabf6debce26d0367dcb199617518cd5a391b5fc2bc70ff2acb3de41c7344a1808f90008d51fc3c0d6ff9dc51851988ac85fbd0bc3f3c70b067df0aad67cc727b55b84047c34908720c2cc51c09a8a911c6f50dea05c12f2e7d15d8fa348a05544bd5eae327ea057d088b6a3bd012a5b7db312ff3d9e8181001f78f0d318ceb2a453310cd003f8977d4d64baa872614ce2a58cb75b3a0914c4aa562ecc826d1317ebdf3e4e051016f37a9c8086bec76f22cf078db41816ac399177538e45760aef1d22a3e8b8651ce4ac5cc6a6ab8f19729ebc5369791821cf54c1e28462e87226945efcfe0ff7ceccb7f594a3027f3c48f336371b29b1f34b9223fa647fd3b4e1fa4de8a98385d93a7528fbb759fd20f359d4be1a67cca2dce39a9e4a0de14f1e3572823e1926f3713971b4bce499c67d31390177a9e1232603658c03101187184b1d30286425f3d3535777c9e03596654fb1dd918e71b0f2076b99952f7015f89a1807e624bffb10d3b021d039222775d30b7b524dda5e20b2b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138436);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/15");

  script_cve_id("CVE-2018-0294");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve35753");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-nxosadmin");

  script_name(english:"Cisco FXOS Software Unauthorized Administrator Account (cisco-sa-20180620-nxosadmin)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, a improper file handling vulnerability exists in
Cisco FX-OS Software. Therefore, an authenticated, local attacker can exploit this via CLI 
commands to create a unauthorized account with administrator privilages that does not 
require a password for authentication and will not show up in audit logs or records.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-nxosadmin
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6cae479");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve35753");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco bug ID");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0294");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'FXOS');

if(
  isnull(product_info['Model']) ||
  product_info['Model'] !~ "^(41|93)[0-9]{2}$"
)
  audit(AUDIT_HOST_NOT, 'affected');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '2.0.1.159'},
  {'min_ver' : '2.1.1',  'fix_ver': '2.1.1.86'},
  {'min_ver' : '2.2',  'fix_ver': '2.2.2.17'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCve35753'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
