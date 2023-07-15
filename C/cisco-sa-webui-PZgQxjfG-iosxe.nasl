#TRUSTED 6cdf6b2d3debcab23c553c4a18df0435a9206c739851612178e8821e3f8f3e6627219013bbc1866d32f2fdc11445b4f79745778458ab34bf0439663fa5ad1bb96853d2161ef09cbc9ab56e3d6f482eac20ed49fe7ed9e7e11da4b9f766bbcd7b340f66448c104921d03f1a553f59eff71902b5fbd5056b41b1e9ea287dded23aaace781ddc62a05dcb37097df415e71766cbe55e4a333dafea8cd2f8e8d6f61ba6bd879b58cbe4f0aed8fe7b4b282f1f353f835f5bf3e85a3670de5f5fe6b784269a1ca6786c7730d44bbbbdda313084efc07aaee1456022a47e4f1243fe133f47cafe737cd62dad249a375b5b2b9cb40733e7fecd87261aeadc68350422344188aefda5d21733bcec31fe38205268603d01d844edf295665dd0fe1beebf0c4ee7e7cfb2fd2b120432220cedefc723059abae23fcb8f6fbc11227e211d49181ac101215b74afaf516c8562134fe351e19f15dc354a0fcef3028dd910fcf0541b20f2548e89fddc61922f583a06551bf2f5147fa30bbee9b8e17437dbe3abec282ecb9877daf69893f47161e19cc3f251ebfa1f7fbc35428047d5be0ba0a16cb2c86e72e6cf0289204d8a0fb23aa4470f49121014e3c17c9ca00207fa7d0015c9d42ab7fd46fb9b696ca3e7d280251c7d941cbd2e89935a3b0a1b23bb7ac6e708b10bd7504a4594a4106d831fc25d3ea542c63f90fa30bf52f7123c2fed7f1be9
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138148);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3229");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp95718");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webui-PZgQxjfG");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Web UI Privilege Escalation (cisco-sa-webui-PZgQxjfG)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by Web UI Privilege Escalation Vulnerability.
A vulnerability in Role Based Access Control (RBAC) functionality of Cisco IOS XE Web Management Software could allow
a Read-Only authenticated, remote attacker to execute commands or configuration changes as an Admin user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-PZgQxjfG
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a073145");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp95718");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp95718");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3229");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/07");

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

version_list=make_list(
  '16.9.5f',
  '16.9.5',
  '16.9.4c',
  '16.9.4',
  '16.9.3s',
  '16.9.3h',
  '16.9.3a',
  '16.9.3',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.4',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.8',
  '16.6.7a',
  '16.6.7',
  '16.6.6',
  '16.6.5b',
  '16.6.5a',
  '16.6.5',
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
  '16.4.1',
  '16.3.9',
  '16.3.8',
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.10',
  '16.3.1',
  '16.2.2',
  '16.12.1y',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1',
  '16.10.3',
  '16.10.2',
  '16.10.1s',
  '16.10.1g',
  '16.10.1f',
  '16.10.1e',
  '16.10.1d',
  '16.10.1c',
  '16.10.1b',
  '16.10.1a',
  '16.10.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp95718'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);