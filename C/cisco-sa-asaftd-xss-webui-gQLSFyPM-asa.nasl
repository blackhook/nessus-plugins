#TRUSTED 726bbbbf9a96735bef3f759cdc56bf0457eb0ac66dba62b23c4ca816443dce453a75459506f56581127196f98a494d328aa512d0cd56e4085d016336d6237a2991627d07c34af04540b15fa3f63d8a71e47a6f69d4adb49d15a0d4f36910c76df2f3bf9b5546d635f88abf8cb4be094c5eb33bdeb522675d03fac8b72be34b150a065f5da7be9d47c282b9e5d9044950f4ca75c66b7fed28622e5ce01c490a6df39e51859ab32e4ca30566d063909d567dc522fc06143f261aa68015ed6c96b6bd5b009139b1912501342bee816e258487e36f1d78b356de19aa9d60a2e1421fd063f619f008e33c321b8adb4717bef7e1d4ebdd107ca596ec6cbc8a5ba5c68fbfbd16ccc58e376e404272470fd2bb7c21774cab9b19b2d1f94c6282cb12f15a8c8eb5696220041df438e3cb46eccaaa4802ec817416c6125d6511537d0146bcfc17da7b29299e406776059cb15553fddcae7a4876a1dbc75e0aefbd4c888fe452038436d1758b96d1555f6618d79f1d58fcebe313147f3237a0e62444c33cb9a774315067a268f64478ee302e7f08d80d2d18353cb2da46ba317c3fea29cdddb57410d22fe26bf40ff11c8e32267ec10d985d99fe0000a0fe54a0e7d896fb7a93c4e05baa4ebbce484b195e7a6831c4d5ce027d9e2b6280f37ef5c7cc3a9e4a4493e6fe6262f3c2a8e0a88cc03072906f8cdf62516dae9da5bc6c06b46219ca
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155676);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/07");

  script_cve_id("CVE-2021-1444");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy20504");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-xss-webui-gQLSFyPM");
  script_xref(name:"IAVA", value:"2021-A-0508-S");

  script_name(english:"Cisco Adaptive Security Appliance XSS (cisco-sa-asaftd-xss-webui-gQLSFyPM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a cross-site scripting (XSS) vulnerability
in its web services interface due to improper validation of user-supplied input before returning it to users. An
unauthenticated, remote attacker can exploit this, by convincing a user to click a specially crafted URL, to execute 
arbitrary script code in a user's browser session.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-xss-webui-gQLSFyPM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?327076bb");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy20504");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy20504");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1444");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '9.8.4.40'},
  {'min_ver': '9.9', 'fix_ver': '9.12.4.26'},
  {'min_ver': '9.13', 'fix_ver': '9.14.3'},
  {'min_ver': '9.15', 'fix_ver': '9.15.1.17'},
  {'min_ver': '9.16', 'fix_ver': '9.16.1.28'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [WORKAROUND_CONFIG['anyconnect_client_services'], WORKAROUND_CONFIG['ssl_vpn']];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy20504',
  'cmds'     , make_list('show running-config'),
  'flags'    , {'xss':TRUE}
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
  