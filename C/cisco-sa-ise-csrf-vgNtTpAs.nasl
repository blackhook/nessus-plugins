#TRUSTED 5a7a984b054440e59d7a4a9042d501111ba6999327462ac5346bbd5a150cfabee1a7366caa0de7cb07961c690f9393ec311b45504d26472c86de3abb907034e818d724cb26a954f339007623b12ea4bfefc88617033c7c60186e3bc2348566f959e871506b37b4f8528f145e1017bd118b759a7d14539c47c7c4d178df08286ea3c73bc921c465daf28476c89081696fb83e99b9de923105ca2634cc52b985e90ad6e83a5a911d31978c44f909b8e273eb317501a7109aa1033583f7d783e3f9f6f9ddea627ba7c2e8a7cd4a0029aaa34287eab8e8d0323d20d0b42f79725c157bca16020fd6eafebd1f651a7da5c0b38e2dbfabd1842d6bd11932ef11a744330198e9ecf75c3ec38b9fc9f581b5b4c1d5ac1afa9b05da9b12beded8b8620e430b0433abe591053d116686add636e03a931cd5c482981aa2c0bbef2baf9f91167ce4d23454c2e64efd6e75717d9ca3577ffcc77c7816df1dedfac24d77d0d03cdaf2f6ca462b7e43ddff710f445efa9844c82e4d837859e5555c1f2842842e20ea28cc7fbd0a953a428b26b60f2df02b2cb82c75298198c8cab5271b39d3420797e93f1b00f307f343bd71dfc70f36d5dd146216e287843c844dadd0439c9645f9eef59e198664e6f260fd1b2fcfd81884c1b3a455173b40f759e9ec509e6e0fee678b26e345d44ccc3d75825ccde0c4a5452e724b123bf8034126346def2ace
#TRUST-RSA-SHA256 8e41dc321d5511cb98d50e241ce53357e8d90c51a6883096f0130e2434615265bace878d8de7821a70c7a7f346338d420a6dbbe8edde001eb6c6bffaccf8e0f111755d07c56c0b27245d164b148f4a501a6fb6fbf159b85588286214f188faf6eb139797eb71222ee6d485c22fb8990609c31fbb7c155582a7918ddb3a5003254e990218071c81cac5fd78585d85806b9e49842ac5f8c005f6fe55cedddca0a1f5ab4c075597e494111e8637fdf7d4aef17897017d476ff67211a9662b0d33e3e3d834d9473e123f02f502ab9ed0076e4f4d98dee48f39f3ab662616bc9ecfda11fec63d1dd2026ed6b3b6fca2c620310a6136388b95adb1c0a7f5d6811ff67c019dbfb2105d6477a0ba08a8825358fb5e798b5a8f08a9fda30a5e17b20990ff6aa973ee49c2810f111d7fa8ae47b1476b9f4696c6025b1332c14f17c79a27fb61aaee73f383a15689fd734e6c0705a013e06f841f9ce8bffe495ba83671a1b9400406acdbd8b40dedf45bc607557cfa5451f32c18ac797762cd2a4a0cf011819798052a73ed56907c566d4a790944f085596c0b751203919e98d65f25631ee7ee6bb357c520125f65e89ba3e27b89c301dabe4d3d1d2137cc25dd51095bcd523576b1075451d1ca14a8cc7ea802f298ab9543c6375e1986601eee6596f22d3cff45fe10836102dbbd9b944b635824acfc01148a1d345f6d4cdaa0634af2413e
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166915);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id("CVE-2022-20961");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb75954");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-csrf-vgNtTpAs");
  script_xref(name:"IAVA", value:"2022-A-0462");

  script_name(english:"Cisco Identity Services Engine XSRF (cisco-sa-ise-csrf-vgNtTpAs)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine is affected by a cross site request forgery
(XSRF) vulnerability due to insufficient XSRF protection. An unauthenticated, remote attacker can exploit this, 
by persuading a user to click a malicious link, in order to perform actions on an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-csrf-vgNtTpAs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86e31211");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb75954");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwb75954");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20961");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'0.0', 'fix_ver':'2.6.0.156', required_patch:'12'},
  {'min_ver':'2.7', 'fix_ver':'2.7.0.356', required_patch:'8'},
  {'min_ver':'3.0', 'fix_ver':'3.0.0.458', required_patch:'6'},
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518', required_patch:'4'}
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

if (empty_or_null(required_patch))
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwb75954',
  'disable_caveat', TRUE,
  'flags'         , {'xsrf':TRUE},
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);

