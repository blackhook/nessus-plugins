#TRUSTED 70fb47c7cb14e7419ffeea47021221ee58b6902d9632b559f1146c64e4adba420173769a80042a29e0bfd122bf51f98207dcae1b4604e9ad7059db035a4b8323d5a3438e33253fe875ad9bc16a559042917883ca4a000f13086884952849a7f3f1461664357c7939c17c33672a49bc4d82a5ac51636496e3ff0aae0bb21a19e74265aa38b8e4f74d1b2511b8ca5266997f2a8bae6da5fa864ed5fa6c1828eba1702b2a3dd34cd81d7686d51d1eeeae2be43f06068c2a1db5666cf3bd424d203af7a15cab69dea60e2a9513f75b8d3b57f8b279024699235e84fb3f1710238ad1e24f1d4b4d34568cb96e38561ae42d5b1b7cf344a680f66dc379d48fd1400f9c960d68b0684cfbb83132287fb552ef097e81d7a1bab2fe2f8014bfc01045fe36a00d7898b51844aea51b755d422fb2fdf9fa8df05ea18fbdc80cce776753c2eca7546ace6877a435e8ad19b775cc40d59b277193870a024399b1ece2d8f2a434d3a9b6be0e0f5e002393479c9b05a182df114cfd3b9cf9c065fe0b34c17cfd12024827bda77685f76847f62044f10078ac569ba8f1a39769035a06c59406a14983dd03d6a4ce6520f0572cf7491575dd5b59a765699100e699cc8224112f102d4f6c537556578cf59885041310e4f6fd7e8b6990401505451c11709874ed96bcf4240ba45a7c34700cff91e05b15afc482951ec6bc8140fb2ed11deab6d4de66
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129827);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-12670");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn43123");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-iox-gs");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software IOx Guest Shell Namespace Protection Vulnerability (cisco-sa-20190925-iox-gs)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the filesystem which
allows an authenticated, local attacker within the IOx Guest Shell to modify the namespace container protections on an
affected device. The vulnerability is due to insufficient file permissions. An attacker can exploit this vulnerability
by modifying files that they should not have access to. A successful exploit allows the attacker to remove container
protections and perform file actions outside the namespace of the container.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-iox-gs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0e1d008");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn43123");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn43123");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12670");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/11");

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
  '16.9.3',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
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
  '16.6.6',
  '16.6.5b',
  '16.6.5a',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
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
  '16.10.2',
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

workarounds = make_list(CISCO_WORKAROUNDS['iox_guest_shell']);
workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvn43123',
'cmds'     , make_list('show app-hosting list')
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
