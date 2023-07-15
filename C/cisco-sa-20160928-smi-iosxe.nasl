#TRUSTED 7eb964373ed45410630e4bf21afaf0b7f3ddff6615b2cbbf68b00aefd8d785389a4d3d729edb081d707248169ce6803508d265685d5fecf1145d23001c2ff0ca6ab11e50ff71be468f4b7cb7bdf75786a0ec04a878e33fb6a40916abbe64f54d836e83c2666bcd6ba83a782e166dc31d9573d9165f34f5077833237ff4eeb3f4630d75fc6739334cd9c6426688604bb3efcea4fe273a800ccbf5e949542bce1a85f8945292333c091985f534b6f3e575178335465490d93587ba4f2d95d276003bed7485ab9b8c17bdbf3a4ad99188574793d325bb9b38f3ee7d59fbb164f58891896d13f55f9ae06c6e2585cd0a67bc70d7f91495716a3d7edb71a4a5d1d6296ec538be9693bf32fc4f7a000e6e570074c8f8c69421f4cb5b3c085b3d8bb988d6613be41846852f102f1ca34eccb4218aa15f1d4a66724d8b54b43451dc3f786a211de2d9c03d1cbeb866dab4429af7a31d67574a518e8f6f6c5bbe58273369fce6d3256f18c106719a387c350322dcd30962f14b5e839093754ae19651ea7da0a5708c172bb65eb36fdeaf1aa503ce4c1fc0817ff2a6692124de719f74729c35d23a2fd72bf5c0c959d78cbd7d3c4ced19bd0a9b824cc939db43ab606be487188db05ac445ba18e8ad3e08c3013717c0bcada9b0372cca5ab19790d2858d9b7438ffe1cdb256302b4ddc217ce486b271b81dabc3fb1e65dd2d54c4d9fea59a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130767);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2016-6385");
  script_bugtraq_id(93203);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy82367");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-smi");

  script_name(english:"Cisco IOS XE Software Smart Install Memory Leak (cisco-sa-20160928-smi)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability in
the Smart Install client feature due to incorrect handling of image list parameters. An unauthenticated, remote attacker
can exploit this, by sending crafted Smart Install packets to TCP port 4786, causing the Cisco switch to leak memory and
eventually reload, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-smi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b04d6eae");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy82367");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCuy82367.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6385");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '3.2.0SE',
  '3.2.1SE',
  '3.2.2SE',
  '3.2.3SE',
  '3.3.0SE',
  '3.3.1SE',
  '3.3.2SE',
  '3.3.3SE',
  '3.3.4SE',
  '3.3.5SE',
  '3.3.0XO',
  '3.3.1XO',
  '3.3.2XO',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.6.0E',
  '3.6.1E',
  '3.6.0aE',
  '3.6.0bE',
  '3.6.2aE',
  '3.6.2E',
  '3.6.3E',
  '3.6.4E',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.2.0JA',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.18.3bSP'
);

workarounds = make_list(CISCO_WORKAROUNDS['smart_install_check']);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuy82367',
  'cmds'     , make_list('show vstack config')
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    reporting:reporting,
    vuln_versions:version_list,
    switch_only:TRUE
    );
