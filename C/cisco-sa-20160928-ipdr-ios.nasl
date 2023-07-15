#TRUSTED 8a3f3502f2ba444eb5cd77347d9b4a2d833aa9954402456f16c769fd3d90af8b202c3e3c2dd464b2f0db16e975bf606d071f0dd65b20a521c22f69b1e8d1cc8f8c86e584cf41e19d9511a9d50d354355fce70211fdd0d85a1d2526321fec5796d382180496d7999406fff5aab99e17228f1605b67fa5a4750a36f9e08574a280ec2b16c4d77c6a9418f6b111b44b62fea3f10a069e453aa9395a3954752039c9bd5ea40d45417f7675e393680a87d40c5d11ca409d10c9fd1336282f5c620ba8fc97e1d159ea9447d76edb3c8a326d1a53afa551bcc1f61b80e0e1b3f637399af0a6438d7e15f76907676cb41d097f53d4b4024e23db40ab7878cc64896adb5e2377c6400c8c2729344774a7d852559df76ba07e08f1d97a6c12e849564405bbd830d6758b3b8f30bab5187a592bd021f325f7695dd5e8c8ac9944abd982a1a23009583183440cde5b6737c33ef7617f9ab9e49c97bedd0790a9ccd5e17ba143e6930988ad0693d32f36f395e2ac86e2887f3cf5c057dd9552885beebb69598b7909f763ac150751cd948bfc306f49cc1960fb5ddf5d055becb3b86700be4b597e15551d36c30a3c1943de95a1f26fe266528bda3b9777622db3fd209f2c08b2d69dc83201c603f511102cab91910f3392a7e2288e3ddbfe515821d0d27c3da7e08120130d83d3ad3c755a4c80c17306bce5176c4b6c8c08f3c954d67fe72e84
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130761);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/06");

  script_cve_id("CVE-2016-6379");
  script_bugtraq_id(93205);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu35089");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-ipdr");

  script_name(english:"Cisco IOS IP Detail Record DoS (cisco-sa-20160928-ipdr)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a denial of service (DoS) vulnerability in the IP
Detail Record (IPDR) due to improper handling of IPDR packets. An unauthenticated, remote attacker can exploit this, by
sending crafted IPDR packets, to cause the device to reload and stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-ipdr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3196a03e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuu35089");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCuu35089.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6379");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

# Checking models with regex, since ccf only does explicit ver list
#
# Cisco cBR Series Converged Broadband Routers
# Cisco uBR7200 Series Universal Broadband Routers - not a specific model on the software download page. 
# https://www.cisco.com/c/en/us/support/docs/broadband-cable/cable-modem-termination-systems-cmts/16044-7200ubr.html
# suggests that the last 2 digits might be free.
# Cisco uBR7225VXR Universal Broadband Routers - a specific model on the software download page, uBR7246VXR also exists
# Cisco uBR10000 Series Universal Broadband Routers - only uBR10012 seen on software download page

model = get_kb_item_or_exit('Host/Cisco/IOS/Model');
if(
    model !~ '^cBR' &&
    model !~ '^uBR7225VXR' &&
    model !~ '^uBR72[0-9]{2}([^V]|$)' &&
    model !~ '^uBR100[0-9]{2}'
)
  audit(AUDIT_DEVICE_NOT_VULN, model);

version_list = make_list(
  '12.2(33)CX',
  '12.2(33)CY',
  '12.2(33)CY1',
  '12.2(33)SCH',
  '12.2(33)SCH1',
  '12.2(33)SCH2',
  '12.2(33)SCH0a',
  '12.2(33)SCH3',
  '12.2(33)SCH2a',
  '12.2(33)SCH4',
  '12.2(33)SCH5',
  '12.2(33)SCH6',
  '12.2(33)SCI',
  '12.2(33)SCI1',
  '12.2(33)SCI1a',
  '15.6(2)SP3',
  '15.6(2)SP3b'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ipdr_exporter'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuu35089',
  'cmds'     , make_list('show ipdr exporter')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting, 
  vuln_versions:version_list
);
