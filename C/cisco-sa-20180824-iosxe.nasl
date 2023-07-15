#TRUSTED 5e5cbfc82b03ef9825fd93c05682f4b9f688c8d1b705ea0fc3ebc37791f5bf08a3bcdbaa7738d431320f2224a12ec9253736854f00da190f4fac1a662abf91c89eeb3b6e3b69fa442be1116612be6c75b3571610969177b7d6af81d7136e336ae1290c87f8db802648347e6f18eb029c1143957866ebfc7e595841031134d87fb46e66bccc27716643ffad7cb0b289ded330ca49f21d5412a39e1153e1150a132b57e8098a15860e3202975b86d64599108d97d632379dcfecfe9a51cf11e850ca957ab769cd1b4e13489de017e3505f11bdc5019ebabfe0d37bc120f806d9fe0fff83a19ed5b845db2b9589cbe49c5b4c20c22eae01cef4d039eac5574816a3d6a1375a0e4c0f52d684e78926724586914a4901f14b752dcf9033ebaaa48b855022ccf2a042885b95bea6685b47cf47ab2aa10b8316542b504a19efcbb21e878d5879878fb1fb845a7529c79cb7e0bf8869d6d8ccfaca2ec9419d326b07462ff0313d12e5a88abd9d609e88f5f030c094e6634d00cff9e3f4321bd041e439d53a85720cafdcfe2db3fabcf016a6cc18543bc034c883c13d09b7abadd45b103150319f9cccd435ef65c08f74e6862d30d8250f687306a474a60c770dc5c6b2e86856ccd90a2a83b2e20b0191910b1782c643ad572560574439c977e22bd0b43b253e3192651f8c6f85aa2f1eaefc8b7139e0309d6c4dd44581bab9126438ccc7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123515);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2018-5391");
  script_bugtraq_id(105108);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm09121");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180824-linux-ip-fragment");

  script_name(english:"Cisco IOS XE Software Linux Kernel IP Fragment DoS (cisco-sa-20180824-linux-ip-fragment)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in the Cisco IOS XE Software
due to a Linux Kernel IP fragment reassembly vulnerability, known as FragmentSmack.
An unauthenticated, remote attacker can exploit this issue, via stream of
fragmented IPv4 or IPv6 packets, to cause the affected device to stop responding.");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm09121
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cbe6eee5");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180824-linux-ip-fragment
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d625ffb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvm09121.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5391");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
    '16.4',
    '16.6.1',
    '16.6.2',
    '16.6.4',
    '16.7.1',
    '16.8.2',
    '16.3.1',
    '16.3.2',
    '16.3.3',
    '16.3.4',
    '16.3.5',
    '16.3.6',
    '16.3.7',
    '16.5.1',
    '16.6.1',
    '16.8.1',
    '16.9.1'
    );

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvm09121'
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_versions:version_list);
