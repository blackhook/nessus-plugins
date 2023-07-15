#TRUSTED 1a049654e76e521ae73848ce26c01b65e82f70416631ec19b7a593f880fc1bcc14e5cbc454e65328111d195c6ec1b49e5639ea7e2bf50083be75fc05741cd5719b81c32c43d07d152e76d3430fd7b98b1e88153a02f9b6fadce80b2ac8d976a8c49887c242aeac0ddc3f4b31771b167aff289df79369def98cc2b048bac73fe10c9c35b6dd5b4a7a1f08271b29f06628ed1bb035fe79bf56f7298dd7d902dc56bb2f27c7645e694f9988f6bfc1cc8beb1bd25b0f59e91785322d3172b7b555b22b1cc557e6e42d7651b3941f09d603342cfdf104bc970a3a4e2de8f3b2b50feb10d8c97d7b5a8d6074b906be71c9d64ab97e2174f67844dc540c90f532f39d1cd7831ac4d3679d06efbf37d1b220e0d4b0111d270a6428ebf89a12b1eeb1890163364a03ccc71d6bb6dd1abd1a609ae573131a63c2019511f3b9fea91ab78f4dc986bb715029072eab49fb95483672dad559ba045665c23b77f1718615e6c14523cc36b0a97d434cf827783e3c5c1560053327c04814146366b97badc7fe6becb6beb0cb663f70fb91936b53f698d9446394d63f47b8c3fee97f20fb2280db0ca3ff480bc83183798e240369ee8e3f78c0988e02708ad69a6b104abb61def0005e882a74a3a4991ce9eae0332813758c5acd549288e69e958d1dd6900efdda3a6f7f88457fef3205cb1877f8cd313f1d121966325ed0a24a43b7565d94be0a44
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131165);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/06");

  script_cve_id("CVE-2016-6393");
  script_bugtraq_id(93196);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy87667");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-aaados");

  script_name(english:"Cisco IOS XE Software AAA Login DoS (cisco-sa-20160928-aaados)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability in
the Authentication, Authorization, and Accounting (AAA) service for remote Secure Shell Host (SSH) connection. An
unauthenticated, remote attacker can exploit this, by attempting to authenticate to the target device, causing the
device to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-aaados
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c26f7fa");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy87667");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCuy87667.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6393");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/21");

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

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '3.2.0SG',
  '3.2.1SG',
  '3.2.2SG',
  '3.2.3SG',
  '3.2.4SG',
  '3.2.5SG',
  '3.2.6SG',
  '3.2.7SG',
  '3.2.8SG',
  '3.2.9SG',
  '3.2.10SG',
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.7.4aS',
  '3.7.2tS',
  '3.7.0bS',
  '3.7.1aS',
  '3.3.0SG',
  '3.3.2SG',
  '3.3.1SG',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.1aS',
  '3.9.0aS',
  '3.2.0SE',
  '3.2.1SE',
  '3.2.2SE',
  '3.2.3SE',
  '3.3.0SE',
  '3.3.1SE',
  '3.3.2SE',
  '3.3.3SE',
  '3.3.4SE',
  '3.3.5SE',
  '3.3.0XO',
  '3.3.1XO',
  '3.3.2XO',
  '3.4.0SG',
  '3.4.2SG',
  '3.4.1SG',
  '3.4.3SG',
  '3.4.4SG',
  '3.4.5SG',
  '3.4.6SG',
  '3.4.7SG',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.1xcS',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.7S',
  '3.10.1xbS',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.2aS',
  '3.13.0aS',
  '3.13.5aS',
  '3.6.0E',
  '3.6.1E',
  '3.6.0aE',
  '3.6.0bE',
  '3.6.2aE',
  '3.6.2E',
  '3.6.3E',
  '3.6.4E',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1xbS',
  '3.15.1cS',
  '3.15.2xbS',
  '3.15.3S',
  '3.15.4S',
  '3.3.0SQ',
  '3.3.1SQ',
  '3.4.0SQ',
  '3.4.1SQ',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.5.0SQ',
  '3.5.1SQ',
  '3.5.2SQ',
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.2bS',
  '3.17.0S',
  '3.17.1S',
  '3.17.1aS',
  '16.1.1',
  '16.1.2',
  '16.2.1',
  '3.8.0E',
  '3.8.1E',
  '3.18.0aS',
  '3.18.0S',
  '3.18.3bSP'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['aaa_fail_banner'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuy87667',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
