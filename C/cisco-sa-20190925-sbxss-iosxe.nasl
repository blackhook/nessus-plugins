#TRUSTED 3608704ff58e42cf2a9da50264f3d11c87e46a2ff402e690f62ce5b408ec21ac8e7e3f69bf0dfa8d44aca26a6bdb18f51d9de0589a4afac5fc4170a9e27ffafb9f1436c05dc8c966740be262b6cd366513f18dd53f694ab9788b08cb4b2050dff7ac12f431d72585263c328b3928ba568165aa6f30978a8863e990d48bd8cb45169b1c6a2709cf64a8b2797881e0bbbdd163b78c4ae90309bf861d6fe61616c1e90cab686a0b18b804ecad2912e022f372bb2ea47c431ac9c9217cbe70834c09b279e6ede310bdec9a0309ebb26a29b21fb1ab264bb16c1b66614c031ff7ad2afd241fb1986a18ecf10bd871d88ef1bfb85c560c46ad38c8c4ff6f2b66843d5e5670ff114c6239cb4ae0cfe61e1ccffac4e3a56ff18fa782590d8491a9c8e4e3d78d81986bd2ce1ca669b59d6d7a6e8b3a69a23c4f9dd6c9cdd5ee565fb4b8a17e534c9e55665a42e198a7e443e0260ec8c5f523300794a7846869bda11d817f6a2482424bf4355fd969d601822a7b78b50354b2cd99c87d29e60891d02e2adaa830ab7c74ac86ac1d14e8020a789e7855cfe8c4e753bbc341de1c571d85370f4f30096660cfead537f733d861e589496250bc0cd2f001f6461a2771a9206ad0b684f3ba023dad003cd13f52fb8154ecfc72e66a2b9a91b46967f5e79bf4711b1180ecd515c9df773d259494c1673d3e5b45ca3b365985de7521838c1d1451b3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129826);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-12668");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk25852");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-sbxss");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software Stored Banner XSS (cisco-sa-20190925-sbxss)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a cross-site scripting vulnerability which
allows an authenticated, remote attacker to conduct a stored cross-site scripting (XSS) attack against a user of the
web interface of the affected software using the banner parameter. The vulnerability is due to insufficient input
validation of the banner parameters that are passed to the web server of the affected software. An attacker can exploit
this vulnerability by crafting a banner parameter and saving it. The attacker could then convince a user of the web
interface to access a malicious link or could intercept a user request for the affected web interface and inject
malicious code into the request. A successful exploit could allow the attacker to execute arbitrary script code in the
context of the affected web interface or allow the attacker to access sensitive browser-based information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-sbxss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5eb43f8a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk25852");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvk25852");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12668");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

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
  '3.9.2bE',
  '3.9.2E',
  '3.9.1E',
  '3.9.0E',
  '3.8.7E',
  '3.8.6E',
  '3.8.5aE',
  '3.8.5E',
  '3.8.4E',
  '3.8.3E',
  '3.8.2E',
  '3.8.1E',
  '3.8.0E',
  '3.7.5E',
  '3.7.4E',
  '3.7.3E',
  '3.7.2E',
  '3.7.1E',
  '3.7.0E',
  '3.6.9aE',
  '3.6.9E',
  '3.6.8E',
  '3.6.7bE',
  '3.6.7aE',
  '3.6.7E',
  '3.6.6E',
  '3.6.5bE',
  '3.6.5aE',
  '3.6.5E',
  '3.6.4E',
  '3.6.3E',
  '3.6.2aE',
  '3.6.2E',
  '3.6.1E',
  '3.6.0bE',
  '3.6.0aE',
  '3.6.0E',
  '3.10.2E',
  '3.10.1sE',
  '3.10.1aE',
  '3.10.1E',
  '3.10.0cE',
  '3.10.0E',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.4s',
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
  '16.3.7',
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

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {"no_active_sessions" : 1};

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_NOTE,
'version'  , product_info['version'],
'cmds'     , make_list('show running-config'),
'bug_id'   , 'CSCvk25852'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
