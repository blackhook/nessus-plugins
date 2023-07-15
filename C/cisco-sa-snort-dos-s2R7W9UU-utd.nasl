#TRUSTED ab552e8cccb8a052609335c5265f98e2a7defa1bb57f8f51810f4e9d1d5693db448d3eec9818a21be2e476f186316ba2799ec451cc36861f90ae91334fc5e8ba842cac9f158dabc66700ca928db15771e633a73e453ad1b60ca16f9910a5f2ed8b007738f507ad22205b743eaefe2bb9a108813d09ec90e776841af31882a242b862c34fdac399ef207e6303a47d1f1507af7ea91eb620a3ef87c52372d0119d3c753f574158307043ee80cc6e7e3ae942e3226b1f91416b7b5e4619ce2a2d3afae59ed4ed89337598a11e613f47e5574fd8a037faa6af41a996f80e068c105ebbed68f18035c296efb04a2b3041522a1ab259a5ff29995f13f8e8f488f33361e5af470fc0c7ded3caaace56a528edaccc825c5e05766a1983c560a5777ba01712d22fe6a10d5b267cb1eb90c5df31b6cc803fb9829acbf91f80e466e4bcf05d5f5c2d57d1912ad9b5f9eafec81282a545f9dd6d00fba229f503a53c45f6fb31d60f0d5c7b92bf906555ea29c2ec8d2b8950cad4bbf6d656a386e785fd20d1c9032ca065051cf2b6d9df9dd21c487fc9b0eaed6c57915ce3a4a76e82fe82cbf81ab000f0f80d753ac06697e09fb4983a7aeee04fe5ee863fb2f8ea4facfd4a5fa22932206a3248161f39618b7f1d2f536cb91fbb27392f48db6f36bb52b3b42b9466e5ec55d78189243cbf6a90bb0004355dffddc7d6579ba2dcffe3a8d448b7
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161865);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/07");

  script_cve_id("CVE-2021-40114");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt57503");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx29001");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snort-dos-s2R7W9UU");

  script_name(english:"Cisco IOS XE Software Unified Threat Defense DoS (cisco-sa-snort-dos-s2R7W9UU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco UTD Software is affected by a denial of service vulnerability. A denial 
of service (DoS) vulnerability exists in the way the Snort detection engine processes ICMP traffic. An unauthenticated,
remote attacker can exploit this issue by sending a series of ICMP packets which can cause the device to stop 
responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snort-dos-s2R7W9UU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3be003ee");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt57503");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx29001");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40114");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(770);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# can't detect snort currently
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Affects Cisco ISR1000, ISR4000, CSR1000V
var model = toupper(product_info['model']);

if(!pgrep(pattern:"ISR[14]0{3}|CSR10{3}V|CATALYST8[023]{3}", string:model))
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  {'min_ver': '16.12', 'fix_ver': '16.12.6'},
  {'min_ver': '17.3', 'fix_ver': '17.3.4a'},
  {'min_ver': '17.4', 'fix_ver': '17.4.2'}
];

var reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt57503, CSCvx29001',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
