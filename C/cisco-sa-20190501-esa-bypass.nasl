#TRUSTED 66f4bfc5a6077675c6f1813104c764f0148d844663a4f86bbefdce274d4b79d38a198c85bddac06372a260115ed645ca5f799d0d2d52e7541c0b65fe48cb1305533610bd6ce5a6acbcad7688cd53814bd6fa7fa55c16431d841393583328770ec02d0dc54ca3cdd7e69605ecf8091b59948445e1130e61fbf35e6fb997c5e4f139ba86244b9bcbb0bbe5f36d183b30767f8d13133a57f4d96bc5568f97733126b4ee583c7dcc3953e2f0a189498d32ca3746b6ec4191b18aeeb7148694e328aaa71a704e8aa6c02fd246494b9f4e0e20d0798d1638c1df19bb7963192717398e19614fe82f8f14fece5779ccc740f00ddb9cf0da704a4f6cd6424ad4d79a7c1c8b0089d6b42b8a0d5cabfd4630648b0ffc1337ffc32fe34915094b698c754ed8434b194904c4eba2b00f9e775d7fcd7038d5c51f30e4cc9eb9f193ab4d1270de38a737ff1fedf31ad3ddf3a7aa6aea257204a5620b6f3678f423cbca10dfeea49c1260748927f74fd3aac767031da1e70dd1566c7c9290de90faf360fc28c4b547c1fddaefb4b1968fb8e6ba0ee52d7a77ef9364c142e2e0b107730b4bfb261714fa572fe0ac272a2208488d06b1095c01fb5d60c93d5b219dad6e0a656dd5df8e0ebde15971a0a536b86061d18688e497cfe7eec741b49b67111502972226bd78c1a0ab6509d15a819fbc7db041733a6cd7843851a4993046b2f1b3468fedb8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126823);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2019-1844");
  script_bugtraq_id(108149);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm36810");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-esa-bypass");
  script_xref(name:"IAVA", value:"2019-A-0243-S");

  script_name(english:"Cisco Email Security Appliance Filter Bypass Vulnerability (cisco-sa-20190501-esa-bypass)");
  script_summary(english:"Checks the version of Cisco Email Security Appliance (ESA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance
(ESA) is affected by following vulnerability

  - A vulnerability in certain attachment detection
    mechanisms of the Cisco Email Security Appliance (ESA)
    could allow an unauthenticated, remote attacker to
    bypass the filtering functionality of an affected
    device.The vulnerability is due to improper detection of
    certain content sent to an affected device. An attacker
    could exploit this vulnerability by sending certain file
    types without Content-Disposition information to an
    affected device. A successful exploit could allow an
    attacker to send messages that contain malicious content
    to users. (CVE-2019-1844)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-esa-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?995db1a1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm36810");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvm36810");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1844");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

vuln_list = [
  {'min_ver' : '0', 'fix_ver' : '11.1.1.030'},
  {'min_ver' : '11.1.2.0', 'fix_ver' : '11.1.2.023'},
  {'min_ver' : '12.0.0.0', 'fix_ver' : '12.0.0.419'},
  {'min_ver' : '12.1.0.0', 'fix_ver' : '12.1.0.071'}
];

if(product_info['version'] =~ "^11\.1\.2\.") fixed='11.1.2-023';
else if(product_info['version'] =~ "^12\.0\.") fixed='12.0.0-419';
else if(product_info['version'] =~ "^12\.1\.") fixed='12.1.0-071';
else fixed='11.1.1-030';

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['display_version'],
'fix'      , fixed
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_list);
