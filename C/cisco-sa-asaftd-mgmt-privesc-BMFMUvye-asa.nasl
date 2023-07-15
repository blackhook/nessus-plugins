#TRUSTED 5afa2f3287aa2c4e7d85422cdb59c09c38e8823ccc10bb9a8ebca1f8f03b01e1455e5346c047a041529fe78e1b9ee36521f0f7c774d465e05d402db3c57f66388b85b1f7379e36166f0b34cda55ef6dd4be2ef15339eae2146662e202e4fe9a3e18e08a6ad016ffe6bbc285a3ba8d4be48033fdc76ae8a51b0aa27808d388650ed165be5b77b062f1e653f909fe97c4083bd919eb0ba81629c6b71baa706a12a5412f933e586c3f201f2e20e29c7f8605242c1f2f85e995f9f28ab8733097d42aa0fab0bb2d2249ef3214c36c36af460d4313da7a953e93bc70ee7ea7575d0e61f28d6c32a7c2256fcabfc6c9871ff90e9f161e2fe93a906509fc8e63ddb4760fb807e3a415f28f8a679ea1fa5beb0b4a5d65f471034bd8acf06aa5e9fef0bef0a6b9aaaa8f77119436286c919b90cb58d10f12f49f9a034d880f447b1658336462230e207e18adc1d717d3cfda037163916e6dbbf7d67c3c612a39f61d41f343d57b957798a892acd932a6746991a3ebcb9e62145985de3500bf2bb3774519d8a7c838e6acfb1a5bb6281908b36403aa4ad3d22933dc25a537c7d86680e264217ff908a55c05ba84e648c719f8c1a8e1ca4e47b298c7965d4e1f9d38d071081abfeb00e577d8bcfd7f4184c70846e3655cf6b173631cd58a3b87e95ba9d60ee97e86f5cfcd26bc3ce2f924d75ef5c10295b71f0a525e86b6e1fbb25b9d7b23b
#TRUST-RSA-SHA256 97f3d548007e0ce4584f678d4b904905f415a991e58363edf4a24317cbf3abcf324415acd61c30e8c61e6775cc922d0deac3e89eb31711a2d61f36a5ab12c4ba1aad37237a8b9c477065c366f80a93ec891e8b1bbf18b19ad70c08a4bee9e019be14e9c6236261ed6a85c2e4cce3ce7fb1d238b51027fff39b70cd3832a259d80ec01232ebbf2af200c17d94931e94f6f0f44f049ae04750c1510a5a09d23b29579af09e1b1f3df5726eb94573fd448d502df0d3ba9e3df4793c40951fb6465477823b93e970b643bb7374ba825d9dae67493180a405cb3446d72f3fd87b590fe38c5482cd10c1fa291fda66021c2173aa0e19a21db2be465ec9d954f9fdf8957de6b168ec6c424e42d978924225f986f8bae5842e9a1246675a1bf898d86a98ac6190c38b5ac8df2a0b2809311725cd142f5033ba4c9ceb9128077943ee4a5048aade3d1897c109e850ce941b6c699c0de949fcd298d3fce837f01a8835f94a9d2296dc33b000d0f669d7b2f6900d5be5e0b76ffe782211b14b756ab8c9f067840a1b843c5fc33eca44f3941dc37f6f5337faa0ce20c6e364b874eb596d08c5e330a0c9cd7037edf53158ca56fa926ccb8f93101a29c324166a74f66e9f788b4e4b93fc64a8650a0ddb0c7158d900005b1a4a8efbce28ed00fe5c1f9000baa45a2129c7c98857a53e5fd33873aa00ad9f7de6bab088a204d0373a79432546d6
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161183);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2022-20759");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz92016");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-mgmt-privesc-BMFMUvye");
  script_xref(name:"IAVA", value:"2022-A-0185-S");

  script_name(english:"Cisco Adaptive Security Appliance Software Web Services Interface Privilege Escalation (cisco-sa-asaftd-mgmt-privesc-BMFMUvye)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web services interface for remote access VPN features of Cisco Adaptive Security Appliance 
(ASA) Software could allow an authenticated, but unprivileged, remote attacker to elevate privileges to level 15.

This vulnerability is due to improper separation of authentication and authorization scopes. An attacker could exploit
 this vulnerability by sending crafted HTTPS messages to the web services interface of an affected device. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-mgmt-privesc-BMFMUvye
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f748ef1");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz92016");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz92016");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20759");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(266);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '9.8.4.43'},
  {'min_ver': '9.9', 'fix_ver': '9.12.4.38'},
  {'min_ver': '9.13', 'fix_ver': '9.14.4'},
  {'min_ver': '9.15', 'fix_ver': '9.15.1.21'},
  {'min_ver': '9.16', 'fix_ver': '9.16.2.13'},
  {'min_ver': '9.17', 'fix_ver': '9.17.1.7'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['ASA_HTTP_and_anyconnect'],
  WORKAROUND_CONFIG['ASA_HTTP_and_webvpn']
];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCvz92016',
  'cmds'    , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
