#TRUSTED 77ba5c0aacdabda2e2a1ad8d03211b7f22b467aba70dd1292827625654a0f7a5c0ee979c418eb733513d5ae2c3f0f0d57526e9b2c1f37bb901859f6b291458b31eb61f09a07c25549bccb42c627c701d664c1b9305d9908e6e22c6f1388fb656ac9b41a74f7b1bc6f24e987779d1aa6894dd0f19ccaf96cdd53bfa8345153436c6b792ab6b8557edd5886af44c7039378ff337ad22a5c0128cb550573803f1677ae1d5b7cf9d649cfd76f729d4f1278dba717ccf065b6d4e8fedf03bd8db07b2347a3c6b7f31a8d4c0019a5535f47ae5cb81079df516f79352981445273965cef8c0e77b53ff238ca83969aa7b7d07f51f2149675f4749d9bd8ee00b6195beb7d89183158541b0df07c0148391774c98e85421ff852ed9fe550783e5c43eb23f1122705055b5804ab1de5b767dc26ade711f447389522af6b574d5e23896060f6764de78242b7ac8ef2edd733c401dcdbf499647073dc7ed82862dc9cebbb8261c3bab877206fda9d7d10a27aa346021ae364886d5217946232e6f12b90727bea5ed55afbfaa2bea5235aa4361a1fd083dc7cf8617618891590f658753d028f3e5e2625348030c90f570d13f54facd437a1cb415cc675758f587035fd32d65202fe40a64aa23701a5c87fe51064d1a2d3035db84daa66a7c79d4c1e1a39663c82123e2dd7490a861f6406473385387f70ebc889f1b81c20669b95b89564c8672
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148093);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2021-1220", "CVE-2021-1356");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu94117");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu99729");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xe-webui-dos-z9yqYQAn");

  script_name(english:"Cisco IOS XE Software Web UI Denial of Service (cisco-sa-xe-webui-dos-z9yqYQAn)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by multiple vulnerabilities. Please see the
included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xe-webui-dos-z9yqYQAn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5ba9e2b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu94117");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu99729");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu94117, CSCvu99729");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1356");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.15.1xbS',
  '3.15.1xbS',
  '3.15.2xbS',
  '3.15.2xbS',
  '16.11.1',
  '16.11.1',
  '16.11.1a',
  '16.11.1a',
  '16.11.1b',
  '16.11.1b',
  '16.11.1c',
  '16.11.1c',
  '16.11.1s',
  '16.11.1s',
  '16.11.2',
  '16.11.2',
  '16.12.1',
  '16.12.1',
  '16.12.1a',
  '16.12.1a',
  '16.12.1c',
  '16.12.1c',
  '16.12.1s',
  '16.12.1s',
  '16.12.1t',
  '16.12.1t',
  '16.12.1w',
  '16.12.1w',
  '16.12.1x',
  '16.12.1x',
  '16.12.1y',
  '16.12.1y',
  '16.12.1z',
  '16.12.1z',
  '16.12.2',
  '16.12.2',
  '16.12.2a',
  '16.12.2a',
  '16.12.2s',
  '16.12.2s',
  '16.12.2t',
  '16.12.2t',
  '16.12.3',
  '16.12.3',
  '16.12.3a',
  '16.12.3a',
  '16.12.3s',
  '16.12.3s',
  '16.12.4',
  '16.12.4',
  '16.12.4a',
  '16.12.4a',
  '17.1.1',
  '17.1.1',
  '17.1.1a',
  '17.1.1a',
  '17.1.1s',
  '17.1.1s',
  '17.1.1t',
  '17.1.1t',
  '17.1.2',
  '17.1.2',
  '17.2.1',
  '17.2.1',
  '17.2.1a',
  '17.2.1a',
  '17.2.1r',
  '17.2.1r',
  '17.2.1v',
  '17.2.1v',
  '17.2.2',
  '17.2.2',
  '17.2.3',
  '17.2.3'
);

workarounds = make_list(
  CISCO_WORKAROUNDS['HTTP_Server_iosxe']
);

workaround_params = {'no_active_sessions' : 1};

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvu94117, CSCvu99729',
  'cmds'     , make_list('show running-config'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
