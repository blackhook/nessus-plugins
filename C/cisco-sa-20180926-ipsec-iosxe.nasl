#TRUSTED 7639a412984508062d5e69169e5efed2cb21f0b0046ef24d852aae26c105e9909e7634c377def6be6799fd89b147c6281f285121d3501f2e7f1ed9e7d32771445fb579e874a632fb17b5f2b1b06b7bcf769173fbdf1a8ddfe42262aac4d616a5ed2cba8e75128098af99e835d50b115317913c3e774249d41c8c11fb49d9daf92d1adfa655eaf328496c89c04eb6c5a9a2e680e85625a0dac81193d373702d9308e246a6a2ddf3b1c9db224f84319440bec55ada0cad9c3ee943cf2ec3b3d83e61109d806274634ac811c3580e1330a14f1b6d9310a81382e9fe0e78c47b6df9d6b0a44cfcce4e2eee2d86692dd7e57a085ff7c4568bce54082312f382a943e7614c48bb150e891c5cae332c05cc8e3e3900ee8caefcb8862a7a8ac922dc65b39722d06345b09defe3878ef8d02ff0147d11213f4111219c746e8251954b094820a20927ef3383bbf4c5317ee1a39981d2862d442f34a315668d83355febc190e918aee056a2ac8d8424e7a696388553b94a0e3f1dd1bb237a578fc82cb486161c00c6730d313a00c0b96da444cf4f5138e289143c4333a989c0400f06e47266cd0f207f12a6702746762fda68b8b88fcdedd104ea7bb7d8eb26dc99c1cff7f5a2b46e0095cf750a63f607a98d0f88da4856b5da2b4101df7ba9fa396daf3e399733b5af0013d18bacf4e35b7ee44084c0a3d77368b1c12cedf8250485c80cd5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117948);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2018-0472");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg37952");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh04189");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh04591");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-ipsec");

  script_name(english:"Cisco IOS XE Software IPsec DoS Vulnerability (cisco-sa-20180926-ipsec)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-ipsec
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6892abdc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg37952");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh04189");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh04591");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvg37952, CSCvh04189, and CSCvh04591.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0472");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

model_list = make_list(
  "ASR1001-X",
  "ASR1001-HX",
  "ASR1002-X",
  "ASR1002-HX",
  "ASR1000-ESP100",
  "ASR1000-ESP200",
  "ISR4431",
  "ISR4431-X"
);

version_list = make_list(
  "3.4.0S",
  "3.4.1S",
  "3.4.2S",
  "3.4.3S",
  "3.4.4S",
  "3.4.5S",
  "3.4.6S",
  "3.4.0aS",
  "3.4.7S",
  "3.5.0S",
  "3.5.1S",
  "3.5.2S",
  "3.6.0S",
  "3.6.1S",
  "3.6.2S",
  "3.7.0S",
  "3.7.1S",
  "3.7.2S",
  "3.7.3S",
  "3.7.4S",
  "3.7.5S",
  "3.7.6S",
  "3.7.7S",
  "3.7.8S",
  "3.7.4aS",
  "3.7.2tS",
  "3.7.0bS",
  "3.8.0S",
  "3.8.1S",
  "3.8.2S",
  "3.9.1S",
  "3.9.0S",
  "3.9.2S",
  "3.9.1aS",
  "3.9.0aS",
  "3.10.0S",
  "3.10.1S",
  "3.10.2S",
  "3.10.3S",
  "3.10.4S",
  "3.10.5S",
  "3.10.6S",
  "3.10.2aS",
  "3.10.2tS",
  "3.10.7S",
  "3.10.8S",
  "3.10.8aS",
  "3.10.9S",
  "3.10.10S",
  "3.11.1S",
  "3.11.2S",
  "3.11.0S",
  "3.11.3S",
  "3.11.4S",
  "3.12.0S",
  "3.12.1S",
  "3.12.2S",
  "3.12.3S",
  "3.12.0aS",
  "3.12.4S",
  "3.13.0S",
  "3.13.1S",
  "3.13.2S",
  "3.13.3S",
  "3.13.4S",
  "3.13.5S",
  "3.13.2aS",
  "3.13.5aS",
  "3.13.6S",
  "3.13.7S",
  "3.13.6aS",
  "3.13.6bS",
  "3.13.7aS",
  "3.13.8S",
  "3.13.9S",
  "3.6.10E",
  "3.14.0S",
  "3.14.1S",
  "3.14.2S",
  "3.14.3S",
  "3.14.4S",
  "3.15.0S",
  "3.15.1S",
  "3.15.2S",
  "3.15.1cS",
  "3.15.3S",
  "3.15.4S",
  "3.16.0S",
  "3.16.1S",
  "3.16.1aS",
  "3.16.2S",
  "3.16.0bS",
  "3.16.0cS",
  "3.16.3S",
  "3.16.2bS",
  "3.16.4aS",
  "3.16.4bS",
  "3.16.4gS",
  "3.16.5S",
  "3.16.4cS",
  "3.16.4dS",
  "3.16.4eS",
  "3.16.6S",
  "3.16.5aS",
  "3.16.5bS",
  "3.16.7S",
  "3.16.6bS",
  "3.16.7aS",
  "3.16.7bS",
  "3.17.0S",
  "3.17.1S",
  "3.17.2S ",
  "3.17.1aS",
  "3.17.3S",
  "3.17.4S",
  "16.1.1",
  "16.1.2",
  "16.1.3",
  "3.2.0JA",
  "16.2.1",
  "16.2.2",
  "16.3.1",
  "16.3.2",
  "16.3.3",
  "16.3.1a",
  "16.3.4",
  "16.3.5",
  "16.3.5b",
  "16.3.6",
  "16.4.1",
  "16.4.2",
  "16.4.3",
  "16.5.1",
  "16.5.1a",
  "16.5.1b",
  "16.5.2",
  "16.5.3",
  "3.18.6SP",
  "16.6.1",
  "16.6.2",
  "16.6.3",
  "16.7.1",
  "16.7.1a",
  "16.7.1b",
  "16.8.1",
  "16.8.1s",
  "16.9.1b",
  "16.9.1h"
);

workarounds = make_list(CISCO_WORKAROUNDS['crypto_map'], CISCO_WORKAROUNDS['tunnel_ipsec'], CISCO_WORKAROUNDS['ospfv3_ipsec']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvg37952, CSCvh04189, and CSCvh04591",
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list, models:model_list);
