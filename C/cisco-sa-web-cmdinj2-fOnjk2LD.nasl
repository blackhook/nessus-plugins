#TRUSTED 996072ba29a59bc7af1c811d8a24d4165d97c9e56d8d17e9910c6e99a3b2aec1264325cb37d9aea3f213b7561ece270664d88814cb87dd16780f3bf6467b14a6b66045b0e507b0099daab7ba09eafeaedd066360f437d747b3cbcfd504af1e13f1ddca3dbb09395bdc9f3b64ce6b23c65ddfde819ac0a3a0f7f5cf77af4923074ff363362298ae3be19614054aed8d5ec8d5471a399e5f31d06cb5cb87a15e049cb74146cafd6fa5df7029c5014075a35e3a33f745c4a11e7b763a7ac266795848f563efb27fdc824833ed25b9be12c24775910cc561ca744c85c458b3ed4255dbbaf9f386fb52ed7208e2940fe6b3824b26a712a487b9f81c8bbc9592237b8d025c56e6a523d36353170731a2e708a17f1e264c6821960fc81cf7677eaaae2e97a63d798444132c73d0ae1560c93f595d5a775dfca748cc356d498f1c0739378714d6dd447142b50e1b31289417431d911c04068eb16948ea7167eec8f24a9fe675e11cc2dd0839a0774013d5ade8b873e081471550b7bd064113f711ec5c453c61382a1a68e19dcc50038c9e721808f0671b1ed1e08765d5a0578e4774a4157e357584b97b3acb1d069d3c5c702b869ef03aecaf6a19c02e00a7d6c21fc9c0a157170f608abf8a3cad01bcd1ccbf80641147b3755b39df4286563fec005591dab71f77d2ae040ccf396869a1e3c0da1d630609232d32dae5129d591196da63
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139325);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2020-3219");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq32594");
  script_xref(name:"CISCO-SA", value:"cisco-sa-web-cmdinj2-fOnjk2LD");

  script_name(english:"Cisco IOS XE Software Web UI Command Injection (cisco-sa-web-cmdinj2-fOnjk2LD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected by command injection vulnerability. A vulnerability
in the web UI of Cisco IOS XE Software could allow an authenticated, remote attacker to inject and execute arbitrary
commands with administrative privileges on the underlying operating system of an affected device.

Please see the included Cisco BIDs and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-web-cmdinj2-fOnjk2LD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a672eca9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq32594");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq32594.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3219");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
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
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.5',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.6.5',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq32594',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);