#TRUSTED 303225a620d55ac86938cb96f8ba8ebfc00956ef6aa88263463e9b39cc485f3f6fe4858e2fc364c5603ec220c8097802e3f141fbfa0a161b241fd2572bcb560fc0d745e070502ca58334d3c39dd3f9875186df5a4fe63de712a08e3642e368cedf8a2168baf19e5c21f1af525873b1a1a221b85b1ca6f24cec7e538034f8e2391e496f54924e1ecea2062a063468155dd697584cf5c8e08f176fad639ff2d6561b4654ae520ece33939300b078d493baee5f208c4d4d1bd47b798ffb1d42f5fe36c4b6aa33824d0ddbaaf210fddd522abc1f3b8403f0274baea3f7a98783be68937e0f4b87c67b2cc85645003aa026e36e0672f8e683458d6315a4dba07423cf98f93ea42dc3832940e97eb0cfbaa213e075290f479ce522afc4c6841e6c41f33cb05bb1d7fd945b46cf9bc2bab1b14e34bea195f9c3bf88355b3b203d96d35b125764f6d8f4b5a4ea53b25aceaa5240d32ae54b2e49d39b71b22ba73439147e61d37962bbe99baa5a376767ac1ca5cc344fc591099957c4f69911ca7805e73db6816db7321e6a17b2dd99feb0ccfb0d69e3169dc0f697dc345012dde4683b9b8809fa1154ce3d7e21ab0bd54d66f762c9d2b2d0c44fb5e07925b54f65f269d9000cf699f67293c6b7865c17127551ef043fdf1b3f46c4c8aff837fc9c3e38bf8874f852387cfe1d0d8f4c0230be3ea69b5127e3abe79af73287abfaa4a2f674
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129531);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2019-12666");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm24705");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-dt");
  script_xref(name:"IAVA", value:"2019-A-0354-S");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software Path Traversal Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the Guest Shell. The
vulnerability could allow an authenticated, local attacker to perform directory traversal on the base Linux operating
system of Cisco IOS XE Software. The vulnerability is due to incomplete validation of certain commands. An attacker
could exploit this vulnerability by first accessing the Guest Shell and then entering specific commands. A successful
exploit could allow the attacker to execute arbitrary code on the base Linux operating system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-dt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a86431af");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm24705");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvm24705");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12666");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['guestshell_iosxe'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvm24705',
  'cmds'     , make_list('guestshell')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
