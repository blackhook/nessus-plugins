#TRUSTED 7126a4a65c65f13cbe86e49b4d4851c420ae60eeeefd4b8353aa8bf806575ce771586f3f28032ba476dc863b440e948015c3bd329803e986985a9e53b2864e38913e4af7fe4c195b7be285f6f005bb65bf0cd7e9c8c048de29d868b19c2e704bc08409452ffb1760f448092d5942bddef5c3bbb333d223c30a150780bc604d11cafbb8e26547dde59f9afb83408b192623cd4f24d32195c78101a0fe60afc5cc1d9944b423eadc632c0c69635d6bc2f557360d83cad1da2cb51288979daef8c2c8204d8b103c30993513c9f55909917e9c23acb549931ab6384a1b16a8be2250b2a4027f41b65d6ea8a68b53ab5cfc3e55362be8526a71947458345d754ef59e205b9f2543dbd90f0b021802579a40e57c9fe4bade6a40f87074d418a9aeb6edfa6a601cb011905b9605d58a5127869dac1c5f94807bda0ff7c1c95ab956c584bc8ae457cf74c1241b1d80649140324b041b3ce4328bd19a408c64521303f9c564fb2c322bd500eff4537b996951eeb9bd44a58d3b2b4b061efcc217c75d2e4d9ab68194914786780e3274ae2c09176ee5c9f494a641bb2f3ecedf02f5685a84c81aeb7a0e4abc58011b7dd3833ad56001121700c3a995cf14fdc8de47a235ab395eb117f75099c0d8d87d27a1cabf8da14b0023111f7c1e3f606f993d97ff6496983653f14656e452cf0d7c2d463b51be53abd7a7aa80e82484c7316576864a
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141398);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/07");

  script_cve_id("CVE-2020-3510");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr57231");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-umbrella-dos-t2QMUX37");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software for Catalyst 9200 Series Switches Umbrella Connector DoS (cisco-sa-iosxe-umbrella-dos-t2QMUX37)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE is affected by a DoS vulnerability in the Umbrella Connector component
of Cisco IOS XE Software for Cisco Catalyst 9200 Series Switches due to insufficient error handling when parsing DNS
requests. An unauthenticated, remote attacker could exploit this vulnerability by sending a series of malicious DNS
requests to an Umbrella Connector client interface of an affected device. A successful exploit could allow the
attacker to cause a crash of the iosd process, which triggers a reload of the affected device and a DOS condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-umbrella-dos-t2QMUX37
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?06b0d48f");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr57231");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr57231");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3510");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(388);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = tolower(product_info.model);

if (model !~ "^(c)?92\d\d($|[^0-9])")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_versions = make_list(
  '16.12.1',
  '16.12.1c',
  '16.12.1s',
  '16.12.2'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['include_umbrella'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr57231',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
