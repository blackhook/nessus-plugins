#TRUSTED 268213e6aaa5c5d02104bd2fe91625c17885609fccf5d12c87b9a5078e46b0954724d1842ed3dbbbc4ad934959992589f0e7de49865a6a296bf0fe6c344ca4f30fe5baecfeed3cf950e4eb85b12e90318b985a34c107c94c4ede60a04bed5faba0c24484e9d7b0a7123b70310134c507cd64b3eb58581db44db4015e1f2dccbdd544fc7b0eac354011a9c625269e1df57ef3d23b5895d52daca15676c5a34416fe3cf1f7d5b53fead9eb11789bf6e8d0729bf01a62464843410ffde821fd1f757ac9e56d33023b7ee550c119b0fe3393e3f2068f7d2a4a15cfca0ea18aaef1f329d0b4d9b0f3d56d253cc804292e3b81f81b8410160f08817963175bf29269898a6902ac1fb0fbd9a12e63d63aaee970553b6114908b56cf55dea53d3ecd0c689d0c1fc16d18cb705f9e2c45b46ae6dff83e2741d143355a3951a626c0ee8efa797ea7c96db38ca8fd03155add03e37c5878a262c28093a0019e4d0ccc817c3a6955865ca2a88f18b7abaa619fdf19ce433ff5c4f72af23e7f120043ebf0445cdb975b69c5fbf1306ca40ca1306a9792d26c861fc8480626ba1b5c5b43f69d5fcb3eac8e9d7f5dbcd6714bc096b3d8e91638a5afad9876d52712437e8eceb6ad3a093b85e34f26392e1c5e0cdd5ef653dc0dcb90f73b5430086d5d6fbfb254154e84f7a5187bd731ebd7f0fc97247b0194dd522a56a2aa3ab8166729715e8f5c
#TRUST-RSA-SHA256 a60b7f589bb4ab787f5ee51fd14e9a1f90e84060cc30f46f5da43c78543d53b14ed8b2ccc90fa0483030898a6f22ba861e20bae8ac5f161d87895ad148b0ded3f24f0809e05a61b4cee44b3e80efb5219542788c6d37b313b412a3121e8ed816e65c72ad798bb0cc5550f334bb2d0e9fc6079636499654d0194ed5bc88814c29dcb6abd6273b1cdb63d5fbf23470f4047c959883988a03bad46ef01e27dbb9488c09e96a136d3bca0d5806ba1c54ed7ec6bea9527f65404814be1806ab69f20a5ea49ad90386a20a44e089863d5e0d0fb4446a0ca3af25a7b1ad0241781776146e9b6695e2163d4c9026e72c3dae7fda4c5318650bb9f2b53f0dc76e2c8556ecbb4e0e814505af9ed060700830ac7f0e6fe12be885f291dd0a02cf7433df591c2987839e39b9e8fbb3b07bcde885f68fb4b818ba762ab308bd4fdecc45f8a839acd15fba37bbf9803eaec7cc605fe832f447352b03083d60c85d5c6a063139c873d73b72806d4ad208396b6e5730bc3ceca0c2c514e037d633ea8734b390703b51e6e70b9c697abb301b46d6a9da1f4cc9e30ced24aed5e744216e336655b1269a492e15fae2bfb160b7d73ed27a20d4f8b249385c12d87d30406e72799fd0e93e88bbe0b3dec6835c11429803ed4165753a6834b1bc83fe09f8a2d3aa7b5a0ceebcf6d3f695220d8225f45db8427eaf8f7c13a38b781f8bb18e08718cd65c71
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142364);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3317");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs28290");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-ssl-mf3822Z");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Firepower Threat Defense Software SSL Input Validation DoS (cisco-sa-ftd-ssl-mf3822Z)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by a denial of service 
(DoS) vulnerability in its ssl_inspection component due to insuffient user input validation. An unauthenticated, remote
attacker can exploit this issue, by sending malformed TLS packets to an affected device, to impose on a DoS condition 
on Snort instances.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-ssl-mf3822Z
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?724078ed");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs28290");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs28290");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3317");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver':'6.4', 'fix_ver':'6.4.0.10'},
  {'min_ver':'6.5', 'fix_ver':'6.5.0.5'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs28290',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
