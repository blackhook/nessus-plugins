#TRUSTED 562b5ada2e4ed1cf9960a19d7baa97037a1c27123d08f6b84aa0e0be9436b54475a269d6d45e38f31ef097fd2214c5866f89e362568fa56660c4e6fcdbe7a8940c8f7720393c6168d3ad61e973197f335fde4f02d5090e742667d929838827df69c6cbf7a8b68fa76d4237957c8ddc569c5c003d3f6913ea7ccbe21d6f407e8aa70b6adf876ba338ae1af0ba7d319bfdfad35fb707dd46e7de33ec0e3bb19ac30adaee5a772df72da33901aefe0d61ba7424595c91f9425df4e55a896bbdafa40fcaaa4a938f1fb9684e0e5c2e37226f63b53cb4dc5277d0857bd1a1b9f13f2331c0f611cb8722e08be9092a8954c2e7f3b1420d767491ef7332dd46e8701b5869347e7fc64cc2585a2843e6baa12ccf894900ae176b9d715067a2aa8f3a3579e00f6a81ce1e1a509e9f7aa9d029640f4fda0631c75d735c0f986b777a093e4e11ef79b24c8f09aefca0a108b1761031e9b93843e93c2d3678c1f66e1bdd192e8f745f30210453eb0d6309a965782500b59616fa677d264bf2d4ab55b61695e7ce6766efd5c925a47b8c0df03e5cc1f3c6fef664ac2a44abf6af3242d33fed806f18e0207be55b3f47be5c9d4bc03aaf6b805a93859e4242ac0178eaf93d475d539e6dee42616e0483822457236b5b72883182a6ba37bda370eb176e2ddbc6df189485ff1c95245116d5757f4f13b59a9822da376f1ff9f05e0051739c6f5727
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127099);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-1762");
  script_bugtraq_id(107594);
  script_xref(name:"IAVA", value:"2019-A-0264");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi66418");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-info");

  script_name(english:"Cisco IOS XE Software Information Disclosure Vulnerability (cisco-sa-20190327-info)");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by an unspecified vulnerability in the Secure Storage
feature of Cisco IOS XE that allows an authenticated, local attacker
to access sensitive system information on an affected device. The
vulnerability is due to improper memory operations performed at
encryption time, when affected software handles configuration
updates. An attacker can exploit this vulnerability by retrieving
the contents of specific memory locations of an affected device.
A successful exploit could result in the disclosure of keying
materials that are part of the device configuration, which can be
used to recover critical system information. (CVE-2019-1762)

Please see the included Cisco BID and Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-info
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?314cb57a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi66418");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvi66418.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1762");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/29");

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

version_list = make_list(
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2a'
);

workarounds = make_list(CISCO_WORKAROUNDS['service_private_config_encryption']);
workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_NOTE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvi66418',
'cmds'     , make_list('show running-config all | include service private-config-encryption')
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
