#TRUSTED 711e743e8daed671bf41ba4dc580207e300dc3752ca4750b2da195bb8d363847544bda247831094084ecd158569ee41f9d526d55d22731f5d90889768879b2ccc0dfaec27c30f9e7a1177884df1c68bf85c943e0b1a58e76aadbb9a4623fd27d3527996eb2b27d65072593878d8b4b9994bd32fe3ec705ac2470364c75d37cde98723be62484bba489bdcae7f82273982ef5e120146bdff3dd55278b90bf9b87291d2f0fef7169604d8073aec875eeb5640bb5dcbb0782b9cb6f775467c867dcaa10d5c49f6da7f1604ae888841581218e26a52ec6757d6a0ebf90ab23dfe8ed49118a1d402ceeb51df983e2131f3a7c031202b6360f48aa91ed457a7d8122fe106a0b5bd49663514e0850611b98a4e229f6badae2534586c18a5b6739728f9a9ce738a935b8de66359ac7ff836370a99c78bdf1bb06dfcb1fcc0c2dd8a708beb100377df6205d35430764a799651b63b7662d2846754206477f4086f2adc24d8de85c91133bc5b927ccdbb4a6c1e8357103ab5c4b7bcd70ab5adfe2aa64cfdc8d38bf88eaf433db57c31598d9543a04cd1168566e19164f47606665d6a802c1a875ed897a31b936b3d83e7efca42ba8365be158c45f5ebea4e922fba1fd94ac13ab66ad9afd2f5d7687513438bf52b08f5286786bb5c3bc0dadbb66e23a1da4cc9661dc007610bc69ae59cf1a2be8d5076cb02a904ef635e914fee13421ea6f
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141172);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2020-3474", "CVE-2020-3475");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs40364");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs40405");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-xe-webui-multi-vfTkk7yr");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software Web Management Framework Multiple Vulnerabilities (cisco-sa-ios-xe-webui-multi-vfTkk7yr)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities in the web management framework of Cisco IOS XE Software could allow an authenticated, remote
attacker with read-only privileges to gain unauthorized read access to sensitive data or cause the web management
software to hang or crash, resulting in a denial of service (DoS) condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-webui-multi-vfTkk7yr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7c030d7");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs40364");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs40405");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvs40364, CSCvs40405");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3475");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20, 269);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/05");

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

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.1.1',
  '16.1.2',
  '16.1.3',
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
  '16.12.1y',
  '16.12.1z',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.10',
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
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
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
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1t',
  '17.2.1v'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {"no_active_sessions" : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs40364, CSCvs40405',
  'cmds' , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  workaround_params:workaround_params,
  vuln_versions:version_list
);
