#TRUSTED 966823eefc6de9a77f4af8356ed0c5041c439278d1220484421bef36163152b8e7bbf896065e736318907e641636fcc6276a749a322de247e170825b010438bff6420fc337b0521ec7b52bb741961ac3ef3a9ebc7f8c3ca11a1402ce763ae9c8a40f2c21321c2d6d493e048cd4c96890492b5283366aa1ec19fc48c22ef51d54b652705df18d3e082ba883c6393ddbcd1eef2adbcde235b9984d2d0aa2405bddba159c0c85f5f32247ddb8ebef4aa6ba688fb36ce21f5aaa456e6ea86a1e878a89ebc88645d5f1d9c5393d46a0a2c89261e67d137601f3bd8b98d8a7e986b34fd35c84200e356047123f978997dddaae517e8b52c08b985818561c469242ca8ec3c30d65e931894b95a998d52811e179a9cc5521800b54bc49a1eaaf806ed2bdadfa1cee297973ec28c65bbac3d7a015dadd0acec13f64eb475ea6dd8610f65b485176ec95a68da1c68ca595d68338d4b6a6715c7a393b2e86c12e8171ee76419de56aa68c7896e2ac51732e80fff737deba3c5b138ce3a8cfc95a81ed7e1f20464c973802c5863a46018d9845ead40ee73e4dcb7e2e4bfd27b97dbdfd3f730660d8af8a3138f99cd45ad4bccedd18ea5286c600b120ecea35a19e3ac30ba4410608845eea9107fb094f135a6e8552d3dda2bf97662dacfa1ac4d863444e0ee2d08e255e8c5489a66391b2207f0bb2e0bc788de20ae16440f757f817cd8fa0f8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124325);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2019-1710");
  script_bugtraq_id(108007);
  script_xref(name:"CWE", value:"CWE-20");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn56004");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190417-asr9k-exr");

  script_name(english:"Cisco IOS XR 64-Bit Software for Cisco ASR 9000 Series Aggregation Services Routers Network Isolation Vulnerability");
  script_summary(english:"Checks the version of Cisco ASR 9000 Series Aggregation Services Routers");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASR 9000 Series
Aggregation Services Routers are affected by the following vulnerability :

  - A vulnerability in the sysadmin virtual machine (VM) on
    Cisco ASR 9000 Series Aggregation Services Routers
    running Cisco IOS XR 64-bit Software could allow an
    unauthenticated, remote attacker to access internal
    applications running on the sysadmin VM.The
    vulnerability is due to incorrect isolation of the
    secondary management interface from internal sysadmin
    applications. An attacker could exploit this
    vulnerability by connecting to one of the listening
    internal applications. A successful exploit could result
    in unstable conditions, including both a denial of
    service and remote unauthenticated access to the device.
    (CVE-2019-1710)

A workaround exists for this vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-asr9k-exr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?04bb980d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn56004");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version or apply the workaround
referenced in advisory cisco-sa-20190417-asr9k-exr");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1710");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");


  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asr_9000_series_aggregation_services_routers");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Host/Cisco/IOS-XR/Model", "Settings/ParanoidReport");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XR');

if (product_info.model !~ "^9[09]\d\dv?")
  audit(AUDIT_DEVICE_NOT_VULN, 'The ' + product_info.model + ' model');

vuln_ranges =
  [ {'min_ver':'6', 'fix_ver':'6.5.3'},
    {'min_ver':'7', 'fix_ver':'7.0.1'}
  ];


workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvn56004'
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    workaround_params:workaround_params,
    reporting:reporting,
    vuln_ranges:vuln_ranges
  );
