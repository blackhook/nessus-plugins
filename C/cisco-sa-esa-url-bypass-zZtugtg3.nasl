#TRUSTED ae0052909af907c348b672ee1b1fb1bb626f3d65cec86fd40cfcfb2d7ac2946eeba99c3455d6a0cae10f318041dc4a58a74d19dfcd1de92819928ae9f165658899bb1a445f19445f9b602bedd53038152ef1dd8a184dfe16d214ed786e0037f08c7aa286b7ee1050544eea169aaead8389a6aafe8060982ba0caba9b356f1df5a4b09e4ee7e5c679936e136242d77224344197fd2048c9f35875e89bd8d4e0441a34e1e00df6e39e329964335f14a077e45a4151a7aa477ccf52bf8bc8e27b56ed796c1bd9969e4bd2e3e1a96edee9aab4847d246481ab2f9be2276eb040bd85819acdff1e7fec6c6ec171e79bdbccc367c48fce95036852aee1a16ff16dfc15e5a0979772beddf0f7ff3f55439dc6454c8f171b81a699086cdf6e8286daedb212bcc5d223ee1b2dba8a015a28b0ba9169b40b05e5d04e8c8c145cb11873c6f0f14d964d9a103ed60ad44d5545849a0475eea4416d0e55c03945674bcf4c39ccab2d9dab1140144fe0079ddb220bb74589306004bfe4427dbcc1357150856fcbf95248fb52cef7c51ef1e1294f91d39a40db756ed78eff12fdf97fa1293a7fde6adaee596cbcf7eb89d7655ca29928566e3b31acc594808e5081bb6eb2ad796755cdb5c1585e0fe46ea8704b346a4ce90ed10235421a73fc845ddedc95f3f8dbf90264f3a1cfdb5fefbed177d2d5120b8f204c8640a75b86976daeb8de1b06b8
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141352);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3568");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu50941");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu53078");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-url-bypass-zZtugtg3");
  script_xref(name:"IAVA", value:"2020-A-0447-S");

  script_name(english:"Cisco Email Security Appliance URL Filtering Bypass (cisco-sa-esa-url-bypass-zZtugtg3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance (ESA) is affected by a URL filtering bypass
vulnerability in Cisco AsyncOS Software. An unauthenticated, remote attacker can exploit this, by crafting a URL in a
particular way, to bypass URL reputation filters and allow malicious URLs to pass through the device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-url-bypass-zZtugtg3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75b266f6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu50941 and CSCvu53078.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3568");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

vuln_ranges = [
  { 'min_ver' : '0', 'fix_ver' : '13.5.2.036' }
];

reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvu50941, CSCvu53078',
  'fix'           , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
