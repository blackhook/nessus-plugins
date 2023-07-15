#TRUSTED 2ae3565c07285f0fd1e3d47e2594433696b3cb2cfecbb1e9ac373e4ee072c602e231ab92379fbee0f4eb64c84543b05cf81058b133c92ff7a87a1ac9f99205e3330e470cb1f91edc193f5ddc86f0a24f92cd464505987dd87488a2c19bad44c8a1aabc35e4c9c5707c13f8e01ea6af7f77576be18688d8cfa8ff2b5ff7dc21559180201e8e3f1a9249e50425a0fe83c2a15ca30764b7cfb52243c3a0a45b2372f32d81292246fa270f573e0dab127eceb8938cb3ecfdac8d401d0bdd995fac9d039196cd0c444de41de8701a14e46f6c03c67d223ad5638555cd00bcfe82be4c41bb9a61b6601c292339d16d8a75f12bbd97eb7f2229e8db71edf1318dab4eca08e6d8595c59c3aa7d343c66716fa34275cdebb7dd35b17417ce4971c229c22dcc98b717885bd378a00a388ed4ce14ca0357e25faf43f883df0fe26fe4f0fe8829c56619af34730a6daa6f81ac1d4b72037aaa9d62fb5137761e57f6417e87314a6a77e8e25d24f04d50daa4a6e35c0fdf8bb3a63f37665a823207bdbc2b9eb87fe7cfe4a504472596725ec2087d3d5f6ef908f4a6218004a7da49df2554aca002b4adda9e10aa2d9ca0d68ee655dca3e63a9c4f7b4bafa8b2fd4003867e598f8a357a9199543af4ddea29667887594481aa25ea42dfcf161ac81ec2fb4ef114dc83e62ea3ccf9f16e606c443cc4e046bcd295deb93041eef9dc7f30a49206bf
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134889);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-12655");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn02419");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-ftp");

  script_name(english:"Cisco IOS XE Software FTP Application Layer Gateway for NAT, NAT64, and ZBFW Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Cisco IOS XE Software FTP Application Layer Gateway for NAT, NAT64,
and ZBFW due to a buffer overflow that occurs when an affected device inspects certain FTP traffic. An unauthenticated,
remote attacker can exploit this issue by performing a specific FTP transfer through the device. A successful exploit
could allow the attacker to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-ftp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35424e16");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-72547");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn02419");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn02419");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12655");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}
include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.16.9S',
  '3.16.8S',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.6.5b',
  '16.6.5a',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.3.7',
  '16.10.1s',
  '16.10.1e',
  '16.10.1d',
  '16.10.1c',
  '16.10.1b',
  '16.10.1a',
  '16.10.1'
);

workarounds = make_list(
  CISCO_WORKAROUNDS['nat'],
  CISCO_WORKAROUNDS['include_nat64'],
  CISCO_WORKAROUNDS['iosxe_zone_security'],
  CISCO_WORKAROUNDS['zbfw_policy_map']
);
workaround_params = make_list('ftp_alg_disabled','ftp_zbfw_policy');

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn02419'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  require_all_workarounds: TRUE
);
