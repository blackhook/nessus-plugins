#TRUSTED 92389a6ee2916c006d52e40539a08273bb89b8458096b390dc4bafd13518f6410fdde965f3023bb8232cde335cf0a1daf6cd44259590b7b835350f83749bcd50c4d55b445bfa2524c21ba2b4303571097d63d261f800581ba682d5b75d80bc5a212403d466a89d60ddf2c32bdd7fd1e4261f2de65893ea57b564dac21146069608ec480e8b355757a65bd241de254c82a6f9c1675631d832aa2c058a4d9784ff71cbf20c571db35db38a4068d7c2469bf2a24924b0c33ed2f847ba63c4a65309e73d6e1fd9269b1194061610bfcabf13bccb8d7e8b007d23d3cba72f2b34350636b97a5288b9d2d19b16cf23ac32cd4f947563f543f7364b6e8d8cdbd8c042a9f8c1576c11780c60b200625bf359a7af7852733df27bc0b0b16e85efc6f4161b2bfb3a9187a22437f93c0f6c5b6cf939258f12340d05f03fe1454e2cf83195f5785f4a53dbc94e0891f56dd820427f80056d4ac069df8bb2dfa3d2c61970738ff25ff00d34fcb19e952a3e5013cd33edf881ac4e98566bdfe75e52d0616eddaf0811c527b794d9b4cbacae8281733d8db5191e721236e3f5133d29deeb24d86dc437bc695bc90b60780376374f3e7827d5b7ed6e190ccec07165437b5483a3b38afb8748f0fbf4933050b938d59bcf89eb0a52edfde8e8291be4c1275bf4290f210efcc8802d407cfbb8c9d7a8e259331ca8c3ae356f53593834fea0a3e7508f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117955);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2018-0470");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb22618");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-webdos");

  script_name(english:"Cisco IOS XE Software HTTP DoS Vulnerability (cisco-sa-20180926-webdos)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-webdos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1fa07425");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb22618");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvb22618.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0470");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
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
  "16.3.6",
  "16.4.1",
  "16.4.2",
  "16.4.3",
  "16.5.1",
  "16.5.1a",
  "16.5.1b",
  "16.5.2",
  "16.5.3",
  "16.9.1b",
  "16.9.1h"
  );

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvb22618",
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
