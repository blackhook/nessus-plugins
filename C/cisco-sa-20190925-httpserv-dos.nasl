#TRUSTED 46509a570d022be0af0d916724b6f900a3696d76b94987097270e609f1a4a5df9e1cf76ec1e4ad7577896824be8f0c453a47d69cf19d83407ede7137328bd4c0da26037dcc99525b7026ab43d8b6da97c8956740e98f20c70daf76ce14661cb2cbe8b141d4c86f8f61c06af3c484f586862aabd7501d105c319b741f75bda1e9e7fd02aef10ebce10d981288a13b26be2ab72083086e70569c9d8207fac218cde7bafd63f7259dd410f83beef85afdd8463e95b86450afd3a368f32f7e492d24cc2f34d161c38d92b387424a671b18f966c5dfb513f50faa4bdab639f80586596637f6dd7a84249e503b16183320c23cfdd5234f713ef762ea808ee7e35047559df00b9b471ff363e18c478dbd3ee49d89dc53b8c1ac86ddd86c6a86080933304bf543aef1fe9d479b26b26f9da01d3cc20539dfe7413be6c1ef32eb2fa59ef771a16d04b92fc80c7ad52c4c2277b5bf4c2d245bd9bf3e4f9fc259e86b02b45a05af2abf15324c14c14679ea946141dd7c16cd91e8e513b52ca6b3f455e3ebda6e1a3360bedfee405ebbd0e55e490f11a35b135ebb162a1a50c13702b81d9750492f3305c747d5ded52bbeb5e211ed55b3c98ecdea5834225e4c0ccf40540112cc802bfb4fb1df075ba2ea6693ac7f60ad8cd75026268dbadbd6de00026787573b85ff38ce39c5a5cffb4637dad6942d276e444bf4bf6671dc8b03b029f8fff8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129591);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-12659");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn75597");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-httpserv-dos");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software HTTP Server DoS (cisco-sa-20190925-httpserv-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the HTTP server code.
This is due to a logical error in the HTTP server logging mechanism. An unauthenticated, remote attacker can exploit
this by generating a large amount of long-lived connections to the HTTP service on the device, causing the HTTP server
to crash.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-httpserv-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?460abc42");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn75597");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn75597");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12659");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/07");

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
  '3.2.0JA',
  '16.9.3h',
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
workaround_params = {"no_active_sessions" : 1};

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'cmds'     , make_list('show running-config'),
'bug_id'   , 'CSCvn75597'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
