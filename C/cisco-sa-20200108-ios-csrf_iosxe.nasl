#TRUSTED 678afc8adbeed01b106420960471a48d59112c056db3d6985b7cea9ca8b2ba3402eb5d35f7bab38a6093743cdba0cbdf3efa2939283dfc3afd52c5f34489a68f23c26760486d7ba603015bfd025166327f63d9eb9c1527f526e8f9b833176f21bdd66f418d0505703373f7f97aa56558816e40eeab05e0f1a53da8381574e2cf63afde716af4aed9b9eeb4478f339bfcf25f6c13a77c3a269f7072a1ec73bf5d4802d44bbe8448d33cd0b39453f473392274e8b6e38183d2c3b36aa7bc0f59898cff90efadd2fc9c7dde23737550682b28f9da68a91093a2e9852a255ad57f2f811d61f01238b8c7b2a1ce83363cd64d2226afc81ad0ebff80eb215ff51fd9092ebf6f0c21364fefb80429e8a78239c559189542802b7afad80aa737b3d758b4d64065607b1d8d6aafff3d8c78b5229f9e3961ec72ffe1d35ec921b6f3935e761792f84c217e5e1f37a87335c866ce690c2c40e5ae57df0f4a465846217e0b9cb663b4c3c3f642652d237c6a1dd8e94e42640fd8671e772d233dbaf9518cdb6e0e622ca6a52eb88182e50f0376f0ba755ec2c5e72bedaf953af168fa08865294b56be29f9debbddbf19a348c141b91fc316cc8c089ae3b74383e4471dfe27a8f7937c60c4bffb1e9fc6a8eb471ab0f45b52ecd318e7ae3f9fc2e2aa9506aa238509ca58e535e8074285dab47bf3cd5a624995530e3aff9e187acd34d8485c050
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133001);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2019-16009");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq66030");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200108-ios-csrf");
  script_xref(name:"IAVA", value:"2020-A-0015-S");

  script_name(english:"Cisco IOS XE Software Web UI Cross-Site Request Forgery (cisco-sa-20200108-ios-csrf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a cross-site request forgery (CSRF)
vulnerability in the web UI due to insufficient CSRF protections. An unauthenticated, remote attacker can exploit this,
by persuading a user of the interface to follow a malicious link, in order to perform arbitrary actions with the
privilege level of the targeted user. If the user has administrative privileges, the attacker could alter the
configuration, execute commands, or reload an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200108-ios-csrf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e39a8725");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq66030");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvq66030 or apply the workaround mentioned in the
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16009");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/16");

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
  '3.10.2aS',
  '3.10.2tS',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.10.10S',
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
  '3.13.8S',
  '3.13.9S',
  '3.13.10S',
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
  '3.6.7E',
  '3.6.8E',
  '3.6.7aE',
  '3.6.7bE',
  '3.6.9E',
  '3.6.10E',
  '3.6.9aE',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
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
  '3.5.8SQ',
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
  '3.17.1aS',
  '3.17.3S',
  '3.17.4S',
  '3.2.0JA',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.8.4E',
  '3.8.5E',
  '3.8.5aE',
  '3.8.6E',
  '3.8.7E',
  '3.8.8E',
  '3.8.9E',
  '3.8.10E',
  '3.18.0aS',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3S',
  '3.18.4S',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1gSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.2SP',
  '3.18.1hSP',
  '3.18.2aSP',
  '3.18.1iSP',
  '3.18.3SP',
  '3.18.4SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.5SP',
  '3.18.6SP',
  '3.18.7SP',
  '3.18.8SP',
  '3.9.0E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE',
  '16.9.3s',
  '3.10.0E',
  '3.10.1E',
  '3.10.0cE',
  '3.10.2E',
  '3.10.1aE',
  '3.10.1sE',
  '3.10.3E',
  '3.10.4E',
  '3.11.0E'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {'no_active_sessions' : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq66030',
  'xsrf'     , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
