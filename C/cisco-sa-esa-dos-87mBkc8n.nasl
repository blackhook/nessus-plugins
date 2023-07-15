#TRUSTED 08201aece80526204c96a55cdb02182041870f4dda34763c1bc3058954c82387317694312c23e2a409232396aa8c849e50c723f955b8b616c5343c864542b18b6af3b56cec78c3a1fd1db4009f3e2ebfe2b5c9dc517c3b405df16989c3703362ec358b31c1d46a23844aff2b8f9930c32a1f79d3f9520d4b3b6778507f0e0650e7521060fc701b3f5d0f334cfba8ed508fb6740aa216216af3a44465bc25e7afc734d3e78952f952107be019a323b0f06b43b86ff4dc0035bc120c9bbe468bc4adc14dfcf2fce40edf8152a12f5e2ecb1e4ee16eabe4f90b4af40e70fb0807202f9b183a168d92fe8f93d9bd110b6ff75449376b3e9ec63317ee492494629904684faf50bee3a0daff9e544ea426c0ce4fcc8668a9a698a5508fb9ca038a4a4f0a5ce0f31fe80e45fde5d0361460a181adcd96daf5d7007599ce5d3c41390e857f006e10574b89e534a42630626784e1cff7e71a7a917e2b48b1253826d9336dd5794b412a556494f142bc3e1da5e5de76921e78192b2a7464dd28a8bc5e25e5d93b82503d58d4f47eca7d0fc1d916723e3bba4bf6b51d8f9ef0df18f58b2688af5089cddc9297742a2d8a7db5fe3814a1add673b9fb2b39210fecebe78ff60f707f03902e60d03981db62999384253c02f944125370205b699aa68b806a5b25db1632e3be18f89ae6cd8d9d751bea9d490dfc893f0cefe7c271a990cb2f24df
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134054);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3134");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq65126");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-dos-87mBkc8n");
  script_xref(name:"IAVA", value:"2019-A-0368-S");

  script_name(english:"Cisco Email Security Appliance Content Filter Bypass Vulnerability (CSCvq65126)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security
Appliance (ESA) is affected by an input-validation flaw related to
the email message filtering feature and zip files that allows denial
of service attacks.

Please see the included Cisco BID and Cisco Security Advisory for more
information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-dos-87mBkc8n
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af260ed8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq65126");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq65126");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3134");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

vuln_ranges = [
  { 'min_ver' : '11', 'fix_ver' : '12.5.0.031' },
  { 'min_ver' : '13', 'fix_ver' : '13.0.0.311' }
];

reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvq65126',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
