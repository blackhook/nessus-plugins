#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160181);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-6627");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup10024");
  script_xref(name:"CISCO-BUG-ID", value:"CSCva95506");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve64219");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170906-ios-udp");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Cisco IOS and IOS XE Software UDP DoS (cisco-sa-iox-cmdinj-RkSURGHG)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability in the UDP processing
  code that could allow an unauthenticated, remote attacker to cause the input queue of an affected system to hold
  UDP packets, causing an interface queue wedge and a denial of service (DoS) condition. The vulnerability is due to
  Cisco IOS Software application changes that create UDP sockets and leave the sockets idle without closing them. An
  attacker could exploit this vulnerability by sending UDP packets with a destination port of 0 to an affected device.
  A successful exploit could allow the attacker to cause UDP packets to be held in the input interfaces queue,
  resulting in a DoS condition. The input interface queue will stop holding UDP packets when it receives 250 packets.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170906-ios-udp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4199217e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCup10024");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva95506");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve64219");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCup10024");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6627");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Settings/ParanoidReport", "Host/Cisco/IOS-XE/Version");

  exit(0);
}

if (report_paranoia < 2) audit(AUDIT_PARANOID);

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_versions = make_list(
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1xbS',
  '3.15.1cS',
  '3.15.2xbS',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.6S',
  '3.16.5aS',
  '3.16.5bS',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.1aS',
  '3.17.3S',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3S'
);

reporting = make_array(
    'port'     , product_info['port'],
    'severity' , SECURITY_WARNING,
    'bug_id'   , 'CSCup10024,CSCva95506,CSCve64219',
    'version'  , product_info['version'],
    'disable_caveat', TRUE
  );
  
  cisco::check_and_report(
    product_info:product_info,
    reporting:reporting,
    vuln_versions:vuln_versions
  );
