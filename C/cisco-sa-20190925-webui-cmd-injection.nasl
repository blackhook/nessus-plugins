#TRUSTED 90fb93230f2b8726bcdc268690d6ad020d670048fbd9e27b1110d37b13b2e6ef0045ac03676ac0e44d9a9cc9b506a7dfbb72bc98617db994f1e89bb3eaab4372433dce122e717beb380afd9df0a4b31f71851e0a7468d7fa5294b716270623a1d7eb6e4ce66c23fcf5eaa1848284beeb537d5c96f2d7e2c95835a06d2418d73e93e2c8975c117099fe27824c916be498d091e17274853da50685245d790278999cb6e58a21a5411ba3be495e62e612e8bb2a970c8e8a85ddc4196fb03f0ae08384e66962266d301418a7e3e02749f5c73762fdecb29dd3e07e38ff9968fc0fb5a9dd2f33494c718011c4517390cd4949dcc17085e7cb2448a5255c44c92e0c915b7106b8f77fb084a2c280a95b74914577d36328c9da95a457b858343dfdf4c25a4de0c66098c3ef77da5618cf9d1cfb1c690ea5c36eec20c6c4cebd84b7ebb07da6348fb2c7d4459537919ea10385cb4c1fd585a7806c8e88db0b65cf98e727978927532922fcee506ca09f34f7471392025ef58459da622fb5d473fddeca9c7f2a8615f8d57a482c264fcc5f669c7e1792dbcd0373e58b0ce81c5131ab9e218eec9a1836bc54581f4854071c51337851e09483f967443e51089d320a0e234440c13ab7e86410148844395e89a95a7eccdca32f9953b861249163d9feb6d1ae5c47b89ad7ade4b2588f4457c55a8244616618c9af03c3add25aaf196783a630
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129533);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-12650", "CVE-2019-12651");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo61821");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp78858");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp95724");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-webui-cmd-injection");

  script_name(english:"Cisco IOS XE Software Web UI Command Injection Vulnerabilities");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by multiple vulnerabilities.
Please see theincluded Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-webui-cmd-injection
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f43db2c3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo61821");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp78858");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp95724");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvo61821, CSCvp78858, CSCvp95724");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12651");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/03");

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

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
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
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
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
  '16.6.6',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
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
  '17.2.1',
  '17.3.1',
  '17.4.1',
  '17.5.1',
  '17.6.1',
  '3.2.0JA'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'cmds' , make_list('show running-config'),
'bug_id'   , 'CSCvo61821, CSCvp78858, CSCvp95724'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
