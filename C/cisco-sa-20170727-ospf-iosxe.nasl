#TRUSTED 8edac6ab33031a4addd1a23f6cc3778e8c69d7e4b7db5ff96281ae7b325435426c150ec371a6c20c3b0da8ca8190e133d6444882e0c7d21d716574fa90fe627a47517be6c3eaed79273a2628041bd8c746e56d8e65fd048969499d7346a01a145cf283c72f05b8b55b00855aaf8fac7515af00ebac1f7cba3e2336a54ecac18c4395654e4f4cb5aecf23b8313e223bb83aa2274766c4fb0e95e9c867482fa75e0a8b3e88cfc8b254ae59670ff330106f3fdb84edfe2ae832362768586a559ad131ed69e9b6c15c66d96ed5bbed7140d71f167af726a41f5204d1edff05c081ccd4e7eb4bacd3403cd7bdf886744a79f184ba2608afd55b3a826a8efcb0cc741528d75a4a2aa934aa0105a051424af10a4b4452899049050e1fa46b53420175b9336c538b5e0441de4a621b9bacc4291b38f32c70145e4086035f8f4c93437a414db3536cf46762b7e04a195ad149b46063bc08e06ea11edd8cf5ef9d8acc72c304762a544dd00e80065b3931b330f5bbb22d7f4a1f0f5e211be2a9826ec72971ae207b6c172866cf2a04aaf61eb11f9ba02a4a10606702279ddc6de2f798cb2d3acd9392482718782b5f4d050c769376cf1775da723e1161b56e59118fec1055ae3de664197391a3a306e27cf4668d980bff3259702ecabd7006fcf3f097e344cb2ec503d64df7aba6b5caf90de30a9003cc64cc4c0384c49366b292bb3adb3f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131395);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/24");

  script_cve_id("CVE-2017-6770");
  script_bugtraq_id(100005);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva74756");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170727-ospf");

  script_name(english:"Cisco IOS XE Software OSPF LSA Manipulation (cisco-sa-20170727-ospf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability involving the Open
Shortest Path First (OSPF) Routing Protocol Link State Advertisement (LSA) database. An unauthenticated, remote attacker
can exploit this, by injecting crafted OSPF LSA type 1 packets, to cause the targeted router to flush its routing table
and propagate the crafted OSPF LSA type 1 update through the OSPF AS domain, allowing the attacker to intercept or
black-hole traffic. Successful exploitation of this vulnerability requires that an attacker first accurately determine
certain parameters within the LSA database on the target router.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170727-ospf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c4d1c57");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva74756");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCva74756.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6770");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '3.2.0SG',
  '3.2.1SG',
  '3.2.2SG',
  '3.2.3SG',
  '3.2.4SG',
  '3.2.5SG',
  '3.2.6SG',
  '3.2.7SG',
  '3.2.8SG',
  '3.2.9SG',
  '3.2.10SG',
  '3.2.11SG',
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.7.4aS',
  '3.7.2tS',
  '3.7.0bS',
  '3.7.1aS',
  '3.3.0SG',
  '3.3.2SG',
  '3.3.1SG',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.0xaS',
  '3.9.1aS',
  '3.9.0aS',
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
  '3.4.0SG',
  '3.4.2SG',
  '3.4.1SG',
  '3.4.3SG',
  '3.4.4SG',
  '3.4.5SG',
  '3.4.6SG',
  '3.4.7SG',
  '3.4.8SG',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.1xcS',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.7S',
  '3.10.1xbS',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
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
  '3.13.0aS',
  '3.13.5aS',
  '3.13.6S',
  '3.13.7S',
  '3.13.6aS',
  '3.13.6bS',
  '3.13.7aS',
  '3.6.0E',
  '3.6.1E',
  '3.6.0aE',
  '3.6.0bE',
  '3.6.2aE',
  '3.6.2E',
  '3.6.3E',
  '3.6.4E',
  '3.6.5E',
  '3.6.6E',
  '3.6.5aE',
  '3.6.5bE',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1xbS',
  '3.15.1cS',
  '3.15.2xbS',
  '3.15.3S',
  '3.15.4S',
  '3.3.0SQ',
  '3.3.1SQ',
  '3.4.0SQ',
  '3.4.1SQ',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '3.5.0SQ',
  '3.5.1SQ',
  '3.5.2SQ',
  '3.5.3SQ',
  '3.5.4SQ',
  '3.5.5SQ',
  '3.5.6SQ',
  '3.5.7SQ',
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.5aS',
  '3.16.5bS',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.1aS',
  '3.17.3S',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '3.2.0JA',
  '16.2.1',
  '16.2.2',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.8.4E',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.4.1',
  '16.4.2',
  '16.5.1',
  '16.5.1b',
  '3.18.0aS',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3S',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1gSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.2SP',
  '3.18.1hSP',
  '3.18.1iSP',
  '3.18.3bSP',
  '3.9.0E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ios_iosxe_nxos_ospf'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCva74756',
  'cmds'     , make_list('show ip ospf interface')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
