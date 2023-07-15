#TRUSTED 4a83b6d4a4fbadc1a53bc6e444e92bdd3511f43310d35490214726c64d14e821e393381e5f61cd51d13ee8f70bf7016ac0e7eb07ca39623c802c9c723d424c4304c1d2f0ffe94c34d892a9363ae1f563090b18d3769aece5628083c000bbe494425f9637a7eeb8d88cc17883007f25d1beed459c92fe88c13d5e450ce8860c2cbf18d111d7e4eaf1030d742d82dc6a15c983ccf7a4db5f521aff87b0bd703ce53b49e5be1106c1e46ccc236dc8a5effc6d6598ef85c6cf77a78dbee1baa8989cf27498816efa1a9d2357549872cae095bc8dbe4505ff6e10934edb2359bd2fd7798b60213ecd07ed68a5da4a1f4d57be16b716b20c4cb1c1ac96d1fc587f263a47c71abdd8c4f77339d00cfbc9822812df1f45acf080263263c57ff5de6ca081fbb1aef7f4ee5140766d796e36c61c2ddbe5ee6c5f53817d6959ebd49fe475aa831d7a34b6a9ebcc55b2c61a2ce974cfe15f1647790d7511bbc1700d912a20b97d3536b055fd6368d82ecccff9402bb172a21d0c4d60ced6a3e57b1c87186b348c72962560ddd4355cebbb09a9c41f7527d326bfe8af3589a784b65ade4071c67b9d6968137fed5407b788b34a2828ca5eca4a66a372e6e1474e2db09b5adb21448dfbf84bd96bdeb92c773037f29e719eaf483a112a7106b910d08da8e83c282eb8535744704f4133796c4b41f477baf1eb7610545c5eae219e3166410acb2b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129536);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-12660");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj14070");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-awr");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software ASIC Register Write Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability. The vulnerability
allows an authenticated, local attacker to write values to the underlying memory of an affected device. The
vulnerability is due to improper input validation and authorization of specific commands that a user can execute
within the CLI. An attacker could exploit this vulnerability by authenticating to an affected device and issuing a
specific set of commands. A successful exploit could allow the attacker to modify the configuration of the device to
cause it to be non-secure and abnormally functioning. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-awr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c9e2875");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj14070");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj14070");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12660");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(668);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  '3.2.11aSG',
  '3.2.0JA',
  '16.9.3s',
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
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvj14070'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
