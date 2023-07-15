#TRUSTED 45cb4f2ee8cfaea887422a4a88296ba34144460000b47ebd905d83171b30f1e88e5b69e89067dbb2373b6e97b261e1ac6ff2f63632d10b78aae9e52c9c9ddb6ceea1472e7f0ef5f81ce62a85109ee0ab85aaa54d1e0afbc94300a5db62c9f5758a1b9164448177255de26e416fc76a7f4d465d21f17fe5dcb39e3eca6762a957a887f9effceef9c8a18178fbfaf3175005acc604cfc8943de7ab706c0201b73ccfa50a7f8c69b491f18cc0bd03e05ee8dc2582ae6df73be8c73c386394369b7829ff756469d0d64012f15dd2acb1151fb5cf66c56ea618a4cdd18a9755faf4cf7da1d5eb09a9fc1f1448236b2675d2b7d40ed6f2a296538c7b09022d4bd44d14850d080ae759a54325f0ff81804dbcf36f07bfe94801dbf42ac6ae26a75cfbfeab1ac3af3f2468d42c2b76351c06da55023be524b9a5f6737a5c3d6368caa34fe6e31a9dd3b87a28e4872b58c38d956a7cd377e55fc550d4c405b4f2a4a945c2028a135442ca0c7292024066a6e17e559b272c5b069eeb9817fda60dc7629cbbca3cd370b0e6744c1acde11b3cf74ce5a8376f42b82877f59219bfe07292285c2df25d4cf128fd52f308012e69c0d6f32614fd355df67376959d005750a70329c509ec8633d691d7402906de50c45d4dd06c9747d51b96639fc870cc9d1870c219c831ff38dd6fba7cd0b8243a77006b5de9a50f5c1636e64011d53d60375d12
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(142424);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/05");

  script_cve_id("CVE-2020-3517");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt46839");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fxos-nxos-cfs-dos-dAmnymbd");

  script_name(english:"Cisco FXOS Software Cisco Fabric Services DoS (cisco-sa-fxos-nxos-cfs-dos-dAmnymbd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco FX-OS Software is affected by a denial of service (DoS) 
vulnerability. It exists in Cisco fabric services due to insufficient error handling of Cisco fabric service messages. 
An unauthenticated, remote attacker can exploit this issue, via sending crafted Cisco fabric service messages to an 
affected device, resulting in a Denial of Service event.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fxos-nxos-cfs-dos-dAmnymbd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?947dee6e");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74239");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt46839");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt46839");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3517");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(476);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'FXOS');

if(product_info['model'] !~ "^(41|93)[0-9]{2}")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '1.1',  'fix_ver' : '1.1.4.179'},
  {'min_ver' : '2.0',  'fix_ver' : '2.0.1.153'},
  {'min_ver' : '2.1',  'fix_ver' : '2.1.1.86'},
  {'min_ver' : '2.2',  'fix_ver' : '2.2.1.70'}
];

workarounds = make_list(CISCO_WORKAROUNDS['cfs_enabled']);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt46839',
  'cmds'     , ['show running-config']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
