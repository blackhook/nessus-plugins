#TRUSTED 951376dd01fd5e4abf416b23d89ca88943c59405dd905508d0811d86fc676f83b3be8d39c7343caff0bb37f88b148a29731083f2c43700d41b957e6bd2f0085e361d15ebce89f8d58381fbdf1f04f08bf244151cee373c061e9ddc672670eb7a5a08ade5c1669eb8b5775893c99dbce4bc60f30fff85effcf737efd5e208fcad2efb7de400c92c2711cea223736f906cc15610904dd6147828c6d3bbbac65229e2833ea16199dbff8946772f07514ac3433cb2b89e75a4931f95856731f77ca4388e24059399c9cc84f1cdfc46627bf30b2cd1390515ee83de68da18861e3bfc551b3c16e24d0710ff2278d856422d007515663d2a2271108b143bfa8c8b7abec2184cebc0b36e924a6f978960bfaa3d029c0f15fb1aa457d1ebb7f2c665c73653b5fae431fd6fd162f661d7bc5520216a8db31904bc268cf9dc624b560996ce394f7a423f2278a0a3ff9d79d56a39f974dff74c1ae94fe137fdd799f5563123d4d3f6f8d7be60036b7ecbe2873aa9eb7ca565713fdec4f2d8329b44b09156b1d3a030727b3a1e7d50ef89505d170670aae3ceac41d9aebc1fba9ae7fae1b19239dc0369c9d68d0e45538e1bc5e38d1fbe34d6e2cbe5482e36c4310675e1c4c76ba40b8894330487d6f9a0a1bdc57b313947492a46eecadbff7232d809a4574f20be0dd91ccac184ebfd45806ce7bd04db1e051d3e28336c0c48e24609c908d2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128769);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/28");

  script_cve_id("CVE-2019-1846");
  script_bugtraq_id(108363);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk63685");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-iosxr-mpls-dos");

  script_name(english:"Cisco IOS XR Software for Cisco ASR 9000 Series Aggregation Services Routers MPLS OAM Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XR Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is
affected by following vulnerability

  - A vulnerability in the Multiprotocol Label Switching
    (MPLS) Operations, Administration, and Maintenance (OAM)
    implementation of Cisco IOS XR Software for Cisco ASR
    9000 Series Aggregation Services Routers  could allow an
    unauthenticated, adjacent attacker to trigger a denial
    of service (DoS) condition on an affected device.The
    vulnerability is due to the incorrect handling of
    certain MPLS OAM packets. An attacker could exploit this
    vulnerability by sending malicious MPLS OAM packets to
    an affected device. A successful exploit could allow the
    attacker to cause the lspv_server process to crash. The
    crash could lead to system instability and the inability
    to process or forward traffic though the device,
    resulting in a DoS condition that require manual
    intervention to restore normal operating conditions.

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-iosxr-mpls-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d35f409");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk63685");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvk63685");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1846");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include("ccf.inc");
include("cisco_workarounds.inc");

product_info = cisco::get_product_info(name:'Cisco IOS XR');

if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

version_list = make_list('5.3.3');

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['mpls-oam'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvk63685'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  router_only: TRUE
);
