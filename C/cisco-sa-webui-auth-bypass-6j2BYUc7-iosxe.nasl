#TRUSTED 330217c373698f6e79e4fc4e30ef04352b16f7e73219de5ca760f8c7ac3c87a7ce544ee430bc84ad27fdf55f61ef32f66211805e75440147bde5a1d54a3eaf25370bf7dd81d6e2a6bf3b5c4b2d20f85cdcc07a21c9a3909c463094a977c204a83ed66cbfe121596a567f6729e5eab44bd6809537dd5bf5b44b34180981c33cb4c3e6c70008de6cf957efbe43efd82dc6f67b71f6c99a2b6f3e156c75232c7a508cd0d904f3546d5e04687c35a3bdd50cc738dfd04e4e20598736705ee2d9c2c61abaec0c7a6f1a9ee3d8c677d5928c11ebb1495fd97fc5082f129c0b2ec8c175d3e543f3b3b1eea424eff6129a600eb9c34331ee2b1372f2f0045ffeb8e085570652be36da75080725ecece35079725558f694c50994138d4136db7bda0f3e85f014d9a0d9558afbad2383277394aa6ec82fed5b7d81b7b415c86d306bf517e3018fcde14e192d1e7db900857fbf124b66efe72773b32c380dd0e3371c3c14e9ed5ceb30940586db657e48b8e5c9a44a14e3280f6312179cb9f354b302343d5c8e58f84b9d074bcc4f3e857b932c0b4697b0aa244599b44ceebc5ae93e776a98562178833708a8960c11ae9833a7b569aaf72863e4cd40602d60dcda87636ab8f630f6feb96b81a3196ee51ff53dce0a2e301362f26e5497c1fcb5cf4a3bc352e8a4cf59da226bb1f51c497222a4ae4b7f243c57c5c74ee899bd75dbd3303c9d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141083);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2020-3400");
  script_xref(name:"CISCO-BUG-ID", value:"CSCva31948");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webui-auth-bypass-6j2BYUc7");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software Web UI Authorization Bypass (cisco-sa-webui-auth-bypass-6j2BYUc7)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-webui-auth-bypass-6j2BYUc7)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a Web UI authorization bypass
vulnerability due to insufficient authorization of web UI access requests. An authenticated, remote attacker could
exploit this vulnerability by sending a crafted HTTP request to the web UI. A successful exploit could allow the
attacker to utilize parts of the web UI for which they are not authorized. This could allow a Read-Only user to
perform actions of an Admin user. Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-auth-bypass-6j2BYUc7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7bdeebf1");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva31948");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCva31948");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3400");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(862);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_versions = make_list(
  '16.2.2',
  '16.3.1',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.3.10',
  '16.3.11',
  '17.2.1t'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {'no_active_sessions' : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCva31948'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
