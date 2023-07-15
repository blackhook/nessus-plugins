#TRUSTED 4fc664c80da2f0823c0aa9f9ce7fa6f1666c884677e0cfb9b5fb113f094b11c42004f22c721c55914fed860e9e18a250d556016c530f24bf373daa3eace2173287b955b32bb2ffe4a6d74a19565bed7dc6ab9390e5ef0599f01dc629b7cc13dc7fe75dfcb2330a6cb0360164856d37bb77d18d1574f7db891f30b7aee8e7fc346edaf32149ae6226dd85da950a4aa759b2b5941faca0384887d51287c92df438ab631090536014473924e277101cb05e349f63a99d58c5d5f406fec4cdc56a3d43294385bb177517cec9973413083f82c235813640b9f84d9b6505039678bf0022c113e38a388f827fb61b68cda02b56fa5dda2e7039d55e5a61588f76b3ab2967d8dfeb1b85a12c6386d9d041e72ba80acbfdc770d3cb313b01b713a2591dadc43eac708968a4a4e305fb8bd1f7ceed263abfbd062bb70bac419aeabe5562c866f3e441ac92e4977664c41923bc76a8895215529f8fb3932a8f09cdad0febf703d0408326306bb646dd80dffc76291624f59cc113af52f34679ccf0bd30b10816a4312ddd969e1b0069d32afe96ba7fe354536e62ba5a6ed037701ca221bc65988bc970551d9f2bc5f47619d0a358ec9ed0fe0f3d8edee42a237b8e9d85fe4e1c9c09334bbf2e050ed96c02492a25d99341c7777731725b1f0e7123c1caa9396bf141e0cfb9aa64f2883780c169d24bdf9ea41e599d2433b2027fb214264936
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137183);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3224");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq32584");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webui-cmdinj-zM283Zdw");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Web UI Command Injection (cisco-sa-webui-cmdinj-zM283Zdw)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-webui-cmdinj-zM283Zdw)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a Web UI 
Command Injection vulnerability. The vulnerability exists in the web-based user interface 
due to improper validation of specific HTTP requests. An authenticated, remote attacker can 
exploit this, to inject IOS commands to the affected device, and could alter the configuration 
of the device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-cmdinj-zM283Zdw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0aed7c77");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq32584");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq32584");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3224");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/05");

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

get_kb_item_or_exit('Host/local_checks_enabled');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.12.1y',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {'no_active_sessions' : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq32584'
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
