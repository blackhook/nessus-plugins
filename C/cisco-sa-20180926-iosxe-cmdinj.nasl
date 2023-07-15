#TRUSTED 18ddc4646e58b32cfdb53819dce37def8b44d5a9d0b3bf74273a81ea33c301683956e09656ff0df881f57f5727100cf05834be291e459fed50722e3957924eaa2ffd413e7f6b23270f99943ff37028ee3a78c6d45f0a2b037fa507c545078920bfdb51d4630949e796a19b03c14069708603dbf3650d4888c3f7d0e6ecbede3cdbe596e1c6fea272ea1d6d2d53f0b4a28a1b0309dea8acb4118f985e931acccf64575f08141e81ad821583be2a2d273a458341294657d844b50ef53b0ee6c37a60e10c7f63dfa32d14336e6eca2cf97fcb2f12cf39e2b7ba39d07258dd8cac52b251a2e3a0ceae88b0bb5e644953a62e071e55783d3264db12cadd29feb1826828c2f1b1813b6d28b0c264ab52f020b244d43b01c8854333bdaeba3bafec1a20871ab5a27e761fd6df3b1410d0f682d672df28113a8471d97a13c05f202946aec9a769d535780fa83f14aaa5b38cd6c06d6c58a0e43820eb4d320adc4689bc6cd9af9cc63bd8521eabe751f32c4c3a5c928e35261c115ef18efa44284785346a5f7b693d8ef4df8711f5e0c6036aa36f9fed611b2bb38a9307ef8d043f6065c23fa20f8b82c2dbae3b694f4cf181a8d055300fdf62d20c0c1518572fdc8950cf4c076f6eeae98c196285bbb6176c24c295d621721fa11d485b0fb85b9786099e3f4c2cc0a6e4c150e1c3606e11b0cd0a1e8c869d78105333f8e3ce9def627e5b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117947);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2018-0477", "CVE-2018-0481");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh02919");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh54202");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-iosxe-cmdinj");
  script_xref(name:"IAVA", value:"2019-A-0097-S");

  script_name(english:"Cisco IOS XE Software Command Injection Vulnerabilities (cisco-sa-20180926-iosxe-cmdinj)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-iosxe-cmdinj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bffcfafc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh02919");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh54202");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvh02919 and CSCvh54202.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0481");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "3.7.0S",
  "3.7.1S",
  "3.7.2S",
  "3.7.3S",
  "3.7.4S",
  "3.7.5S",
  "3.7.6S",
  "3.7.7S",
  "3.7.8S",
  "3.7.4aS",
  "3.7.2tS",
  "3.7.0bS",
  "3.7.1aS",
  "3.8.0S",
  "3.8.1S",
  "3.8.2S",
  "3.9.1S",
  "3.9.0S",
  "3.9.2S",
  "3.9.1aS",
  "3.9.0aS",
  "3.2.0SE",
  "3.2.1SE",
  "3.2.2SE",
  "3.2.3SE",
  "3.3.0SE",
  "3.3.1SE",
  "3.3.2SE",
  "3.3.3SE",
  "3.3.4SE",
  "3.3.5SE",
  "3.3.0XO",
  "3.3.1XO",
  "3.3.2XO",
  "3.10.0S",
  "3.10.1S",
  "3.10.2S",
  "3.10.3S",
  "3.10.4S",
  "3.10.5S",
  "3.10.6S",
  "3.10.2aS",
  "3.10.2tS",
  "3.10.7S",
  "3.10.8S",
  "3.10.8aS",
  "3.10.9S",
  "3.10.10S",
  "3.11.1S",
  "3.11.2S",
  "3.11.0S",
  "3.11.3S",
  "3.11.4S",
  "3.12.0S",
  "3.12.1S",
  "3.12.2S",
  "3.12.3S",
  "3.12.0aS",
  "3.12.4S",
  "3.13.0S",
  "3.13.1S",
  "3.13.2S",
  "3.13.3S",
  "3.13.4S",
  "3.13.5S",
  "3.13.2aS",
  "3.13.0aS",
  "3.13.5aS",
  "3.13.6S",
  "3.13.7S",
  "3.13.6aS",
  "3.13.6bS",
  "3.13.7aS",
  "3.13.8S",
  "3.13.9S",
  "3.14.0S",
  "3.14.1S",
  "3.14.2S",
  "3.14.3S",
  "3.14.4S",
  "3.15.0S",
  "3.15.1S",
  "3.15.2S",
  "3.15.1cS",
  "3.15.3S",
  "3.15.4S",
  "3.3.0SQ",
  "3.3.1SQ",
  "3.4.0SQ",
  "3.4.1SQ",
  "3.5.0SQ",
  "3.5.1SQ",
  "3.5.2SQ",
  "3.5.3SQ",
  "3.5.4SQ",
  "3.5.5SQ",
  "3.5.6SQ",
  "3.5.7SQ",
  "3.16.0S",
  "3.16.1S",
  "3.16.0aS",
  "3.16.1aS",
  "3.16.2S",
  "3.16.2aS",
  "3.16.0bS",
  "3.16.0cS",
  "3.16.3S",
  "3.16.2bS",
  "3.16.3aS",
  "3.16.4S",
  "3.16.4aS",
  "3.16.4bS",
  "3.16.4gS",
  "3.16.5S",
  "3.16.4cS",
  "3.16.4dS",
  "3.16.4eS",
  "3.16.6S",
  "3.16.5aS",
  "3.16.5bS",
  "3.16.6bS",
  "3.17.0S",
  "3.17.1S",
  "3.17.2S",
  "3.17.1aS",
  "3.17.3S",
  "3.17.4S",
  "16.1.1",
  "16.1.2",
  "16.1.3",
  "3.2.0JA",
  "16.2.1",
  "16.2.2",
  "16.3.1",
  "16.3.2",
  "16.3.3",
  "16.3.1a",
  "16.3.4",
  "16.3.5",
  "16.3.5b",
  "16.4.1",
  "16.4.2",
  "16.4.3",
  "16.5.1",
  "16.5.1a",
  "16.5.1b",
  "16.5.2",
  "16.5.3",
  "3.18.0aS",
  "3.18.0S",
  "3.18.1S",
  "3.18.2S",
  "3.18.3S",
  "3.18.4S",
  "3.18.0SP",
  "3.18.1SP",
  "3.18.1aSP",
  "3.18.1gSP",
  "3.18.1bSP",
  "3.18.1cSP",
  "3.18.2SP",
  "3.18.1hSP",
  "3.18.2aSP",
  "3.18.1iSP",
  "3.18.3SP",
  "3.18.3aSP",
  "3.18.3bSP",
  "16.6.1",
  "16.6.2",
  "16.7.1",
  "16.7.1a",
  "16.9.1b",
  "3.11.0sE"  
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvh02919 and CSCvh54202"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
