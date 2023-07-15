#TRUSTED 5d65a63b2293202d085a42da34c5f2f63b1dac89f4f2c4ee902ae856b854021b033a162e9613cd0aec1ce138139eea8b67d222677ea3ac2bfa78547cbdd8d1d66001af03c76037aea08038a6619151658d56f30c0616ddf5b2493ffc4ab7dca360ba63d45e17158ffdec54e79af74a692a172d3fdcc9d23597b5ca7113507fc8f7a603a9271e4b1f1ac8854f927fc8778b1c85c8cbcbdbaee2a0161f173ca76c965b135b63c14e04e293bbec67d5e0ca28af4d1ccba40d3aeb013b547da812c890320598d64f536dcf9dbf0fc4df10d0813057e123d5b5b0a2a676ac44b09148e2afd10f88365d40ff96932cc3b0aa86863b5d886ef40580a83fb2aed20d782a6a273c4baa6ec21f94632e52ad26785a7199f28f551e0a1bd1e6cdc334babbf739a32af9a4fa16a84db5ab4f022dcaa807614ae1e411c98cccda3d6473f4a03729f058a6a92c7979dbaa8effe0a4c7d4fa28c9565ddf4aa17d41a646762cd10ea97969f239876da2d5e5c6e7918e3158e5310ca8e320c487afb1795f79a6e33c1e8c8959c9e4ab5be8a696054a93e4f6642dc11a44634186e17df87d4139d042f13949ae93d520ab3b8d7f9e3c6ab2e39732d70fde4d3aa96656a08d145eb2759eca99033aa31f2ba629d00e897051e5863d30f057589c362934355cc47455aaa9ec3068711dc3384897acf5fad4359e946727a7d1d7765f8ebceb215c6babe6
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131080);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/29");

  script_cve_id("CVE-2017-6665");
  script_bugtraq_id(99969);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd51214");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170726-aniacp");

  script_name(english:"Cisco IOS XE Software Autonomic Control Plane Channel Information Disclosure (cisco-sa-20170726-aniacp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by an information disclosure vulnerability in
the Autonomic Networking feature due to unknown reasons. An unauthenticated, adjacent attacker can exploit this by
capturing and replaying Autonomic Control Plane (ACP) packets that are transferred within an affected system in order
to reset the ACP of an affected system and cause the system to stop responding. An attacker can also view the ACP
packets which should have been encrypted over the ACP, in clear text.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170726-aniacp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f352f2d4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd51214");
  script_set_attribute(attribute:"solution", value:
"No fixes are available. For more information, see Cisco bug ID(s) CSCvd51214.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6665");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/18");

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
  '3.10.4S',
  '3.10.1xcS',
  '3.10.8aS',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.2aS',
  '3.13.6S',
  '3.13.6aS',
  '3.13.7aS',
  '3.13.8S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1xbS',
  '3.15.2xbS',
  '3.15.3S',
  '3.15.4S',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.0bS',
  '3.16.3S',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.6S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.16.10S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3S',
  '3.18.4S',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1gSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.2SP',
  '3.18.1hSP',
  '3.18.1iSP',
  '3.18.3SP',
  '3.18.4SP',
  '3.18.3bSP',
  '3.18.5SP',
  '3.18.7SP',
  '3.18.8SP',
  '3.9.0E',
  '3.9.1E',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.5',
  '16.6.4a',
  '16.6.5a',
  '16.6.6',
  '16.6.5b',
  '16.6.7',
  '16.6.7a',
  '16.7.1',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1s',
  '16.9.3',
  '16.9.2a',
  '16.9.2s',
  '16.9.3h',
  '16.9.4',
  '16.9.3s',
  '16.9.3a',
  '16.9.4c',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1s',
  '16.10.1e',
  '16.10.2',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.2',
  '16.11.1s',
  '16.11.1c',
  '16.12.1',
  '16.12.1s',
  '16.12.1a',
  '16.12.1c',
  '16.12.2',
  '17.2.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['autonomic_networking'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd51214',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
