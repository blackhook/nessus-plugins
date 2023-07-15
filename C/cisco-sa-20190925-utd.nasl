#TRUSTED 8a989f463fb11e1d183e678d750ba2e091d947038228bae08951a433481f6934b13a3c736bfe89314e96dcc017e3f0cf6a6465fad7ab3a3f6c7d7020d894bea6c739d726839945c5986c751297f076c13db1f6785e4531becc9240a761a8067606f4b960ff95985730328fef7d0c4365b003eda002da1d8dc3f190df99768926190eda44abcb39f5b7ef4b41686f0609ff7495a98e23f6b912959a096aedf0793b3e8a029e421555403be818cb917bbf8446f1492882dc19faa82a6422ef2c7df36010363f34b2af448b5e82d5ae25734668f7bb01f0485ca755005244b2f311f32fcaad5ceafbfedc741a19ef29b4e1a1aaa683064336114e6ddb5ead685e07e12cbd08e5086c847e8ed9997fb71a3355900d8046ec5cdd9e447b748c6e9ffe73f44502f0c11e32134f51822611868f92e06ec8dd9dcc1f6ef9bab2e864a439d6e5366422b405245d9289f2a03797a102ce83dc8aa6188bb6d3727b083333da6c3fc8a5424fd52949426f3689a8c2e31321c0a7f2521c95b9496309d0619b67eececf26fd4ff1919ad54419b65fabab5a1271b25daf29999dd6c75bb87e485401d02bf0bca904ebda52381ae52db592ec8b77ce2c7721184c65d43ef85f4a976613a96e888f4daaaf3edb55b0520c68c415d710ce0bd3764c9d71da4114955e6dc46ef657f27967f4822d11728ab21441dcfb1222cdb606b88a89f97bebbd7c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129532);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-12657");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn29244");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-utd");

  script_name(english:"Cisco IOS XE Software Unified Threat Defense Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability.
Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-utd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1237229e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn29244");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn29244");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12657");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.17.4S',
  '3.17.3S',
  '3.17.2S ',
  '3.17.1S',
  '3.17.0S',
  '3.16.8S',
  '3.16.7bS',
  '3.16.7aS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.6S',
  '3.16.5bS',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.3S',
  '3.16.2S',
  '3.16.1aS',
  '3.16.0cS',
  '3.16.0S',
  '16.9.2s',
  '16.9.2',
  '16.9.1s',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1c',
  '16.8.1a',
  '16.8.1',
  '16.7.3',
  '16.7.2',
  '16.7.1',
  '16.6.5',
  '16.6.4s',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.7',
  '16.3.6',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.10.1s',
  '16.10.1e',
  '16.10.1b',
  '16.10.1a',
  '16.10.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvn29244'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
