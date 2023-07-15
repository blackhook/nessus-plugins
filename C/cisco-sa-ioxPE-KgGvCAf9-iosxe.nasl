#TRUSTED 929e4957365a606c2a3550d87a55988cd0503973175d31fc83820b7c1d754fa2a27446b17d4026eface16403644874e74d69a475e7c3c61871a7a6f3f9dc0fbe2a082340c790419715362ec9503b89527e9a5dabce88b81ad42012de259f083aef7dc30b7aad6be59e61bd67333b65a85f47fc1eed15cfcc5aff77bea6007bf96a4a0d72f526bf3cd59bfd565e2dce0f06e6ae3731b19a2fcf8bff1df8ad18a99a9f0940a5c3364377fdb7fac2fbfdf862cdad26c01d90b07495cccfde47169605a0377bbec228653a378098aff4736aeff29fb42c43aa3dbdd9db62638b7f3bf1ba8faf293b4e96fc50609de3bf780b51a6244fab007bdbdcedd59356824661e0af1514dcdfdeccc32c11d10b47c77a900bf3071df0094455e0bf889e693c24f5f663a78d7aa1104bfcc1ae4c88b6acd1db5ffc524ac3e4d5001e82ff86e5bbb0a126d0de76050e50af2c86d41653aa747a2a648a75e4ec3fb74b9466065a052ef584ac862885bf8c44bddd69619a7a16e0821e95caed9c6d7e06915da23337c1805a1a4f03c051a8f19250a735fd04f8bb824897fcd69f4634168b21a6888aed22709d4307259ae390ada1573a2c61d37a38572c764b2585e38403991e0ed02cf809f5b349439221b3759d83ed327cb5261985d2a537f44d89232548cebcc53df46b8afd642d1d219aa9367b59a6c0bdb0f31b745d161297e58a73afe73bf1
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137143);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3227");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq18527");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq83400");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ioxPE-KgGvCAf9");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOx for IOS XE Software Privilege Escalation (cisco-sa-ioxPE-KgGvCAf9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the authorization
controls for the Cisco IOx application hosting infrastructure due to incorrect handling of requests for authorization
tokens. An unauthenticated, remote attacker can exploit this, by using a crafted API call to request such a token, in
order to execute Cisco IOx API commands without proper authorization.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ioxPE-KgGvCAf9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc91c220");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq18527");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq83400");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvq18527, CSCvq83400");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3227");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/05");

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

include('cisco_workarounds.inc');
include('ccf.inc');

get_kb_item_or_exit("Host/local_checks_enabled");

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.9.4c',
  '16.9.4',
  '16.9.3s',
  '16.9.3h',
  '16.9.3a',
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
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.3',
  '16.7.2',
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
  '16.3.9',
  '16.3.8',
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.12.1c',
  '16.12.1a',
  '16.12.1',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1',
  '16.10.3',
  '16.10.2',
  '16.10.1s',
  '16.10.1e',
  '16.10.1b',
  '16.10.1a',
  '16.10.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['iox_enabled'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq18527, CSCvq83400',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
