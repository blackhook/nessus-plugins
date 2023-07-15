#TRUSTED a94af786d5a3c9a5cc8f5bce707ef69974b7baf015c7005d5f137434bed5d5b086095ae63a3242d6153ce8be7e8e71e8af884c78a80b82107c377381ee2964b66c3ab7415b1d5876695642174ca498af2592bc2fcc8597ce336a6220fbafb51142386191b21657fef7f7b636fdec3d384933ca859aaf41568a008bb73f4a30b1d9a95a0881a5a40c8e7a921bd1d1777a61521e270fa86a21cc1804d4b718bdd3c561eaae794213cf96f62c28f0ce01794ca492106a27f53e4e8730f6e17c2ef28f03ec81dbb82425e31594e94b916c9dbfa61c39422d7c574c0aeedede9677dd655c0e38302ae67129c87466e579742512fb4857df2da88e3a281f69d7477e422b18f3abb30a80032b11be96de32a8187299abaec95e52b965816b421a14b31acc5732edf7e7f3e098e43c28ffcdc8803512972ef2e2171d78fe2f66afecb734366a7de4f9fbddaedfebc4a03bc436060db53f9ab9052660c8e75bee1170ad0403fe0db433ec232e3ed66aed30edecebd4c30b700770b620c494ff359a766bd10e1e2f91f4f19e7189d73fe849894470d7688d98870b51aeb93023c957e707b90ed8dfd8517c38a5e600e0214af54e81c6702eddb49e74bdda1869d748214d0a507cedbdca063c4d80baf7a0688f9a51a95ffe69daa2318f58119d548cbe2fd374cca9cb17057312a04c0c8f9444c4d88c3478959b4ec00dfbd228083ba7082b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124332);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/20");

  script_cve_id("CVE-2019-1796", "CVE-2019-1799", "CVE-2019-1800");
  script_xref(name:"CWE", value:"CWE-399");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh91032");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh96364");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi89027");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190417-wlc-iapp");
  script_xref(name:"IAVA", value:"2019-A-0132");

  script_name(english:"Cisco Wireless LAN Controller Software IAPP Message Handling Denial of Service Vulnerabilities");
  script_summary(english:"Checks the version of Cisco Wireless LAN Controller (WLC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Wireless LAN Controller
(WLC) is affected by following multiple vulnerabilities

  - Multiple vulnerabilities in the handling of Inter-Access
    Point Protocol (IAPP) messages by Cisco Wireless LAN
    Controller (WLC) Software could allow an
    unauthenticated, adjacent attacker to cause a denial of
    service (DoS) condition.The vulnerabilities exist
    because the software improperly validates input on
    fields within IAPP messages. An attacker could exploit
    the vulnerabilities by sending malicious IAPP messages
    to an affected device. A successful exploit could allow
    the attacker to cause the Cisco WLC Software to reload,
    resulting in a DoS condition. (CVE-2019-1799,
    CVE-2019-1796, CVE-2019-1800)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-wlc-iapp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc39ed65");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh91032");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh96364");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi89027");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCvh91032, CSCvh96364, CSCvi89027");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1799");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_(wlc)");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");
  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '8.2.170.0' },
  { 'min_ver' : '8.3', 'fix_ver' : '8.3.150.0' },
  { 'min_ver' : '8.4', 'fix_ver' : '8.5.140.0' },
  { 'min_ver' : '8.6', 'fix_ver' : '8.8.100.0' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , '"CSCvh96364, CSCvh96364 and CSCvh96364'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
