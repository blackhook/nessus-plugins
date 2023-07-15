#TRUSTED 7689dcbe654b05fb3f27ae60ffaa319904213b8757c8bcc0927bd768e49e1ff9d150b2b5de92017bbfc53ebedf416ff06d63ed37803c92e425b8dbd4c683c40b801446c35aab7fa00b8e08bd882307d3c2d47f436a8aba1e5314dec9821d5e58bce95cb445c39fddb5dfac22609a2cb465b801a35051a257fd4e37649c2612b97709639dbbf1dc73797014463d9994e56ddfc3e2d126d1e3318877f4308d17c17763f9ca62b5eed1c844f08368f000fc670f8b23b0c41ff0907e9ab3bbd77281fe389bfe9b290a19c6a069320abca40aa23fb3a1e7fa6929203846f1718284a0d581aaeb6e4c722c7012a476ab30438ae2ae319ee94a6f9be38980230d3d8dab248ae766a0886fe3c9b67f87db9e62f16c91836258e4bc6b35fc257cfadba4b4ed54c0cd91d62692ccea714f014a7fcd6b8b7d746cf1748c2d86334e0ed4187ba55d4648a296ad6807e045d48169ae1fd3e9a87161942cad55d530e66e09ec3afedaa962db953f6fca96ed3f277078f8ff6543e70b718632830f8d1196a58a2b85dacb34c772a9ece748422b8c17a1b193edc6e6896fb1a9adb3ded10b0d998aaaf637512ff4bc754cd436bb3d4a41dd1970e5fbbe06249e21ad727ec0ddc4de9317a4b44a13749b309b2e6e1a689da1e105e486e25f5b92cf950168ac8eace3befcc39672bce7bc56554cc1e96828f2da244cdbd98d1741b30586b87abc90ac
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137241);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3212");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq32588");
  script_xref(name:"CISCO-SA", value:"cisco-sa-web-cmdinj3-44st5CcA");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Web UI Command Injection (cisco-sa-web-cmdinj3-44st5CcA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability. Please see the included
Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-web-cmdinj3-44st5CcA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?649b929c");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq32588");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq32588");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3212");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

get_kb_item_or_exit("Host/local_checks_enabled");

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.12.1y'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {"no_active_sessions" : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq32588'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
