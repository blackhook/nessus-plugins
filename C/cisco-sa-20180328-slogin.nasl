#TRUSTED 15991511402c090505ac306fe360c38a97606fc47c964f4c5170e16d3cd7be459d00004cad9b48d8532aad190c348a42a98181eddb006bb631398a721dbfcbca9a37a14824536cedefcb22d43d4a3d6b98ff4ea6aaa2a6f8b37774b03ed26397a469f350de22b0ea2f9f9df344e8ee4b05d8d94476bcd662efcf5b2369f16fc9c05c408c59b3e8c8b5ca461691b6e96ec380b4dccbafb6936aac15dc8ae5ccafcc1f5137063f0cd570c666d51156c737359bbb7e809f0d686769c08c55bf57f6bf8fc312374512c48cd2c91ef2f0a5b85f7577797adb3942067840984913b173659846d0628b86c2c9366706c5ea14ef9009687860edea8b7403870a922a31c0747316ca78e3c6f5e969684921b517692a67fb11bd822e424bb5fc3503549d952d706b3e2ea00fb618080a0c3c40d0897cc897cfdfa0aa51cd23ca32f88445e634293eddc7827885dd8ef67a49ded6a037fed34a3c85b13ed4162b5e410a0d966a7fa1d026979842c5df000ff21dd801a2ad096dcc987769eb2b5f9c57fe4ca2ededfd98a4bf78a6e764987d76754f79684f67a3806d50fb67451dbecb7eb1892daec9ef5492a98f679134c4818d83c9375aff1d9b3a4f6ab60d0d1471cc6d12d2152c9c47ec971e1481f6554e8421632a4f471da4a429e1d4d09079f6200e1c5066ac6f321c8bd368113c50d04f2c31601acad1d387bae7de8b16144fde694f
#TRUST-RSA-SHA256 9c3f0317db07aa21f78ef7cb33ecb0840d7a239268399723dac232d77206ec3c8f5caba71c239e513c0b38a8d74ad4023e0e3121a80d70979e81f4b6f41ae1fa235846ba340bb10321a0c16fd2888b9f9f924f61e8a9cb6c5fc36a13c8d4477faca4bda7430577197c99c3ce55f6e08f0ba6237814cbf8d59b0e016e10b580c8d89233e8ef2e902363b471f2d362190b9f7a33b04483ad064eafd861f01b950024b62ce65c8715c23fb71445fdf6b0c277caaa1a43c965f26d05f3c3e6cf9d9581645200aa0f2d9064571ae5ed510a5eec66de525e878b77044ab323d5be4029d30eaf71967874e4eaca4b73360621c7766ee9e623accd2e5522121e197a417571207e3fa7d5d4a19436a6e1367e44ef8a15f3e84eee8dd009696d5951faa4b8bf6e951969976ce80949223ed3bd6a056c9baa043ec402b9e7279909a85604e02e3ed4eef46d8277c0a07b7622afb30fe811f425a30e1072492ed238d790fed87e4eb069f90f21b5f76521c5d1e213856636fe047c8bf3cd0125a8d8dd55337c0e91a80e5494713d9866710a7fab9696574533d6f363520d5c6dc062f273506cc3c2d02b439df6c4a785f6e4fac7e2a1a0b925eb8c649d3db7f074348ff00bcf4696778cea0e4ce0eb3f8ceccbc5ae2ffd1caa8efa1cc9a751fb74aebe76f69e5e3667ece9bd504d57c67982bbd76a6029a5a2b2778ba4e7492958fc8ae7af89
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131951);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0179", "CVE-2018-0180");
  script_bugtraq_id(103556);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy32360");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz60599");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-slogin");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"Cisco IOS Software Multiple DoS Vulnerabilities (cisco-sa-20180328-slogin)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS Software is affected by two denial of service (DoS) vulnerabilities
the Login Enhancements (Login Block) feature due to an attempt to free an area of memory that has not been previously
allocated. An unauthenticated, remote attacker can trigger a reload of an affected device, resulting in a DoS condition
as follows:

  - By attempting to log in to an affected device via Secure Shell (SSH) or Telnet with invalid credentials
    multiple times. (CVE-2018-0179)

  - By attempting to log in to an affected device via Secure Shell (SSH) or Telnet with invalid credentials
    multiple times while the administrator modifies the 'login block-for' configuration. (CVE-2018-0180)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-slogin
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9aa14dc5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy32360");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz60599");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCuy32360 and CSCuz60599.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0180");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS');
version = product_info['version'];

if (version !~ '(^|[^0-9])15.5' || 'm' >!< tolower(version))
  audit(AUDIT_HOST_NOT, 'affected');

# Only need to check for login block-for, as the other BID covers fewer versions (<15.5(3)M3) and is a config check on
# login block-for and something else (login quiet-mode access-class)
vuln_ranges = [{'min_ver' : '15.5',  'fix_ver' : '15.5(3)M6'}]; # CSCuz60599, login block-for 

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ios_login_block-for'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuy32360, CSCuz60599',
  'cmds'     , make_list('show login')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  workaround_params:workaround_params
);
