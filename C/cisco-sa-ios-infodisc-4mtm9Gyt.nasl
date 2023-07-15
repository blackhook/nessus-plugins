#TRUSTED 1f7e0b291155720ee701aa427f17e6b65e6af00b4b395cd0da15e4226affeaef9ee0584b269b60bb29c9c306fc57f40ee1a863b2d7b418538a17e7a5fa2260eebcf15787b355acfd98a93618b9dc4e492eee123874828a5c30561f05f5c93c3e830a75a6b6243375251ac4c613a129623ffee256990ad193b2c7a84b18d6f9f520c0a40798f550345f989a85e944a3bd6d5aa342105b40269952d73124daa4965b251cdb491b2389052516994aac89e13f093ce8360a1f98c243ef0b37df94b9e925ec314f83e975417044eb43eb52c176eccea44acd2f017208cc9bc6e4fefeed22956c6a52bf69db518d0be2f1fb82791ee73ac2aca3ffb295f25fcadb509373ac43beb6d2616bf779a65969b5b9873ac2867b6bbeae8f5d7cbd9a3b3707017234c2ad42977cf2c8e61924bfd01789013b9a653cea86d0b97c244834a7bc7f5eb5f10a3b4844ee4b07b1c341cded3b6c94b99a6221850456fe30ef775635ea008497b6bc2a9530416a7dbf16380235e338661b406697fb83437e877a72a2f186d81468de75f1996d5ea3ce2929690b07f143c5d8a9b072db7879a0f7f4fcefd2fd54f5be119ac4c394711a2ef33ce662e86575855ae5632f641bc3251741279df31c58538a45d2e4859ddd557972c4830a386e8285336e23629db803d1f60789cf1f0892961fa9edcf3b9271d8dad87a746ec9f7379de1ec2ddc4fe4f017ff
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146264);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-1128");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt41022");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-infodisc-4mtm9Gyt");
  script_xref(name:"IAVA", value:"2021-A-0062-S");

  script_name(english:"Cisco IOS XR Software Unauthorized Information Disclosure (cisco-sa-ios-infodisc-4mtm9Gyt)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XR is affected by an information disclosure vulnerability in its CLI 
parser component due to insufficient application of restrictions for a specific command. An authenticated, local 
attacker can exploit this, by issuing a crafted command at the command line, to disclose potentially sensitive 
information. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-infodisc-4mtm9Gyt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6289e04");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt41022");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt41022");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1128");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(201);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

vuln_ranges = [
  {'min_ver':'0.0', 'fix_ver':'6.7.2'},
  {'min_ver':'7.0', 'fix_ver':'7.1.2'},
  {'min_ver':'7.2', 'fix_ver':'7.2.1'}
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['aaa_authorization_exec'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvt41022',
  'cmds'     , make_list('show running-config'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
