#TRUSTED 2913f6ec1f3f20b9c8881816d08a50bd3e4207de9f0260703d292bcadb610247fa8834717c5a7585d029f49f9a6eb1268bc65f058a215444a6ceef14aa94d0b35e633ebede093e4d1a682853b8348619b2fa681904e3d1d78c3e7e0c66ca269cb1bf1be15014fbc8fe661ab7e6f3fb1e36c37bed21b393bae150a8c46ee32813dd331cc076dfca4acc67254d55492b903cebabf498acd97adbd8f6a0a344e6b72cc0cbddadfd84569330eaf70206b3cd2e59c94ee0376350ad2eab353853dda605304a53b8de540f1a4ada42cccd608804f6860dd9e0df9d37d997f18b70357f59a5ed718e9c874c5832efdcadc596e106ef410ec37feaf8ecc6bf96506b8159d56de61538d2a576d691071ddd940d503a9ea7936f34be2eb1411164111f2c7a1615bf411bd80603fd77d591a571429bec51e7f086db4dcc0259103d4922b1a964706f25b5888007bdd2d185fb6427f160e5981cc53a0fcd5669747f44ea7cb81690c4ca5fd22114fd8ec6d1e2aff92f17f7ab48b335ed5a8f85fcb5b87fc400a48de2beb8e9f0ab720aee684dfcdb634c62c101a69e1b6111bfb87cf8747fb4c37ca6af75b8dd2031897f49a30a3c5f26714bc602727f258f1f54761f1d1e393076c6b88c353699fb9ee43ab793342167cc0ddf170a66f7822ae6c5e278b29aa1430dd9447389b2033daa3559889163272512647563539e419ce8be8758a11e
#TRUST-RSA-SHA256 2cd17aab215a104b645917f2d18dab43e519929fe94aa5241e369706a33b35f11a22d25d79036f514b2d8da38638a424cbe5e9b2a9a7c07cee66104166da4c2ae7c1b3770697e202dc79d682e846b021e9e2d507aacf98e4fc8b846df50246fad9c02b7b72a350f0f5aceb706916ca10595848db638e12f490aa3b8fbfbe4d90aa64e340d34bf7b654cc6baeb2354979145ec0c2525ba21cc6b48fccb84de66cf7fd0446b432de86f42458ff85914ad8ca8a95d90adab34cfda273434ff52d742ba82ad9c396c54c25e3fdf9f44777606ea3bfbca943f4828b808d02ea903f8c5693c4c4e55f94e73e5d2e5bfbab9f56b1191bc42299b8ccc0bb6487ee9975dbe5ad7fbc09879d7a326a784c257d434c7d48f32cc44833600a5bbfcd0e063cdabc05ae79e0c7b755c64cdfcffd8a7c5a6ecc646c3f91ac43e081d2618cd40b16e8dca1daaa917f9a892a931596dcf15211589e17524666fea390c039da0771e7eed1fed229c39b4dda3e8ee59f9ee01fbf4b92335ed97e27b91754425e9fd340c192d164a3aa9d104d06d549b16bd819d0feb94df949b978a4c070842bc5d1ddac339217ca21106f0b01cd19f1eaa14ca9f266c25e2af55b516e32c278211a315a0aa0aff6e37aded674cec8e51733c85d66d7c0164eb9eb8466caafb04f6970ad6911a2621a4fc35c63c7b97b9a002dc011c6620327ca3cd645f401a47fe0e1
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173805);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/04");

  script_cve_id("CVE-2023-20065");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd25783");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iox-priv-escalate-Xg8zkyPk");
  script_xref(name:"IAVA", value:"2023-A-0157");

  script_name(english:"Cisco IOS XE Software IOx Application Hosting Environment Privilege Escalation (cisco-sa-iox-priv-escalate-Xg8zkyPk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. The vulnerability lies in
the Cisco IOx application hosting subsystem of Cisco IOS XE Software and could allow an authenticated, local attacker to
elevate privileges to root on an affected device, due to insufficient restrictions on the hosted application. An 
attacker could exploit this vulnerability by logging in to and then escaping the Cisco IOx application container. A
successful exploit could allow the attacker to execute arbitrary commands on the underlying operating system with root
privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-priv-escalate-Xg8zkyPk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16265c9b");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-74842
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86953f38");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd25783");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwd25783");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20065");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
var model = toupper(product_info.model);

# not vuln models
if (model =~ "IS?R(.*[^0-9])?8[0-9]{2}(^[0-9]|$)" ||
    model =~ "CGR(.*[^0-9])?1[0-9]{3}([^0-9]|$)" ||
    model =~ "IC3[0-9]{3}(^[0-9]|$)" ||
    model =~ "IR510([^0-9]|$)" ||
    model =~ "CATALYST(.*[^0-9])?91[0-9]{2}")
  audit(AUDIT_DEVICE_NOT_VULN, model);

var version_list=make_list(
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.3a',
  '17.3.4',
  '17.3.4a',
  '17.3.4b',
  '17.3.4c',
  '17.3.5',
  '17.3.5a',
  '17.3.5b',
  '17.3.6',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.4.2',
  '17.4.2a',
  '17.5.1',
  '17.5.1a',
  '17.5.1b',
  '17.5.1c',
  '17.6.1',
  '17.6.1a',
  '17.6.1w',
  '17.6.1x',
  '17.6.1y',
  '17.6.1z',
  '17.6.1z1',
  '17.6.2',
  '17.6.3',
  '17.6.3a',
  '17.6.4',
  '17.7.1',
  '17.7.1a',
  '17.7.1b',
  '17.7.2',
  '17.8.1',
  '17.8.1a',
  '17.9.1',
  '17.9.1a',
  '17.9.1w',
  '17.9.2',
  '17.9.2a'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['iox_enabled'],
  WORKAROUND_CONFIG['iox_app_hosting_list'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'cmds'    , make_list('show running-config', 'show app-hosting list'),
  'bug_id'  , 'CSCwd25783',
  'fix'     , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
