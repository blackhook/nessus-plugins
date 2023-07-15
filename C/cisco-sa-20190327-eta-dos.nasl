#TRUSTED 213a962dd8c553cfc3f88a68cc217f1a2999d50d17d525818b517675f06cc1a0de11e93ddddeb22a53425f0233b4641cb9416772922f5556798d2fc1909f77394a48b3cdabea42577cc9155f11d2a588ea309b47b2f9a10298c1c2d0e926a56bf8a689f2c8fa5ba14f77478705f8ec1a2230b9f5821a9f41d146c5714c9ef5ce2f3aa3e0f527abf151b05767760cd63deb4b68364ed6783ec82e321420b710fc9b9164fbd5ecbae0d0e678a3ee913bdf0f80dc6a9a70d46a9bd150bcb17d3ac35149c293a925b64a2dc1f5c8a53f4847744a242b0225d93aa6693fd66dec7485e517146afcba5abc2f70b657dc2ffe54511f24981bc011678438d4b3bfdc5292fde1a0d958f6ac60cd481c0f1331358eeb156ac3fac144aa9a3776d9e9a6ac718d7fb37b7260250eb202f46caf9c3b8001d8f1fb72ae8607e6a617c2d913fb6dc95599a322712d2e6a0a68e747d6b9d6d613c97247310e35ddd021385299146594a8453813dfc92bf8b95aa5b4867f00e4c697767de962d5b81bae4dcdf758eeb359821b3b0afd95cb960cfa8f294a8cead8b254baa2c659f1eac707e5c145d03feee20cec50e176950055b9e1fcacf60889b4443acd26d9e337eca33bdb66dd83af4a3df28cb58ee01828f9871ae3dc3663da4d1578fa177f70b7f1e54ab0e57506a68259462155dbb03e0770f7d8e7870b1d646508457be831e887e27861b1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123791);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-1741");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi77889");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-eta-dos");
  script_xref(name:"IAVA", value:"2019-A-0097-S");

  script_name(english:"Cisco IOS XE Software Encrypted Traffic Analytics Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following vulnerability

  - A vulnerability in the Cisco Encrypted Traffic Analytics
    (ETA) feature of Cisco IOS XE Software could allow an
    unauthenticated, remote attacker to cause a denial of
    service (DoS) condition.The vulnerability is due to a
    logic error that exists when handling a malformed
    incoming packet, leading to access to an internal data
    structure after it has been freed. An attacker could
    exploit this vulnerability by sending crafted, malformed
    IP packets to an affected device. A successful exploit
    could allow the attacker to cause an affected device to
    reload, resulting in a DoS condition. (CVE-2019-1741)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-eta-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23365f93");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi77889");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvi77889");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1741");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/05");

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
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.3',
  '16.6.2',
  '16.6.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['platform_software_et-analytics_interfaces']);
workaround_params = make_list();


reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi77889',
  'cmds'     , make_list("show platform software et-analytics interfaces")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
