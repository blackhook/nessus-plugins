#TRUSTED 63c9235dbd65b57d2ec6d75110f564def1de86dac7ef286cf36dd159ddf9eb7200bb91b029aa989f13a9ac2d52cf75855ef54f10ef8adcc8790bff8e97c6adc1f774ae408dc7c17ac2504752efa51422a0eb84b7d59aaaba8640b8059c5a9c23dca8ceffec90f59d7019ca5d23c7d37cee789dc461177e019918f2c2b48ca73a2df1fe8e289a0bb306d2bfccf38195a4d6ed7c95d766194de4eb7ae18eca29740f039d933687206edb454ea10fbf1099b15922a7334821067a62cfce76b68d70d2f43870fe7797f6cdaa5070f3873c748df2f84706364322dcebe06ba6a334b29c993a1f295a6e5438e09a3bfe9167b0b5269e17d01284ba9cf0ec2f2b433b76d21f9808c72d4727d555716ea6232a0d7d1236707b8b7349fecf397d51edb8287c18e49bea99d79c0a661f189799aa6fbd25d911a0580dd064ba7027346fcf2bb5571eb3f4a3f015de3dc70308bc4a2aa396e9a98aba261171fa1fba8d1131453b22966bac1ed0a99b417c008f6840a48ee6d9165c5e70ae54bc895278f14b6a8aa085377183e41f4f464a28ed73f52f9cc0962684c2e63761089502ad30fd3b2acdb15b2aa19e1e176b045f40aa56f37454d1f6dd0ab21b41148048244a418bc87168d82c6716e0e5e973d8b8ee835bfd67a4758f2b01a34dd61624302c945ddc8dcd0cc88a8dddb6b43438718069c3cbadd861ff941c2a686cd3fab3a9de34
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147765);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/16");

  script_cve_id("CVE-2020-3388");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs11282");
  script_xref(name:"CISCO-SA", value:"cisco-sa-clibypvman-sKcLf2L");

  script_name(english:"Cisco SD-WAN vManage Software Command Injection (cisco-sa-clibypvman-sKcLf2L)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco SD-WAN vManage Software installed on the remote host is affected by a vulnerability as referenced
in the cisco-sa-clibypvman-sKcLf2L advisory.

  - A vulnerability in the CLI of Cisco SD-WAN vManage Software could allow an authenticated, local attacker
    to inject arbitrary commands that are executed with root privileges. The vulnerability is due to
    insufficient input validation. An attacker could exploit this vulnerability by authenticating to the
    device and submitting crafted input to the CLI. The attacker must be authenticated to access the CLI. A
    successful exploit could allow the attacker to execute commands with root privileges. (CVE-2020-3388)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clibypvman-sKcLf2L
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29f83867");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs11282");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs11282");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3388");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
    {'min_ver': '0.0', 'fix_ver': '18.4.5'},
    {'min_ver': '19.2', 'fix_ver': '19.2.2'},
    {'min_ver': '19.3', 'fix_ver': '20.1.1'}
];

version_list=make_list(
  '18.4.303.0',
  '18.4.302.0',
  '19.2.099',
  '19.2.097'
);
 
reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvs11282',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting,
  vuln_versions:version_list
);
