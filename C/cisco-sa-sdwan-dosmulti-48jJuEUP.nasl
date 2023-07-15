#TRUSTED 779ba9e8a2361af9aa84a403e02280c4830fbb4f413c21a3c44b84c152728a650e92f3fd5a83aab19ca040cc153de8f67238dafb7022c914f98a867079243d6085f52b4d46b7a9659caf01fbc780787b89b3389457c1b1a024a39e37b9105bae4bb841d566f776be40e3a73bf8e0f55df202461428364ed6108bb7642712a503142ab5b7084def91c995a4425d359bf592c62560fcab3264ff5f665261a50a3c6cd7f07a0b31eb62e1fa3aaaef3d921569e35456c3e065a39bfe12419159725ce4e26c17609089fb628d9aaa6f51c30c39bb6a970a6498a5080b897e04f4f6b64eea8c90d4aa3562ea8aa99f1dce2e384a736f7a868ddb33349de6faa4d798e228a354224c38e0e2cd3faef42c822bf2b3d02ee014888f03d8db2a64dc882d338fc925d22da76502164ecfe88d933ed74ac90ab39f07d0b99ed3521070b040cb4ac1d5f20fe45889bc368a60f8b22c1fb04faf28e5cee04704c49a4b59a8134ccfa174a12bd91087e0a8f8c58d562488f89e56aa7ae28bf1a3c157ff62ad9ff41fe3fec844f1dbb6ea0c2f1a39cbc0e72678fb45f54f606ff24aa42b74d4915159f2d4f87c02d409ba66651e2b5c02c871f01f2d8086c30843fbd30f08dc8021d60083596aba4bd9791880a2dfcfc12a0ec720ee80c97f1a77e6abaf93c7bf637249fffd9d982d1cc29a894925e7d856ed70afc115df4ecb51581bdb1f98bd45
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145708);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/02");

  script_cve_id(
    "CVE-2021-1241",
    "CVE-2021-1273",
    "CVE-2021-1274",
    "CVE-2021-1278",
    "CVE-2021-1279"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq20708");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt11522");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt11523");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt11530");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28409");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu31763");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-dosmulti-48jJuEUP");
  script_xref(name:"IAVA", value:"2021-A-0045");

  script_name(english:"Cisco SD-WAN DoS (cisco-sa-sdwan-dosmulti-48jJuEUP)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN is affected by multiple vulnerabilities, including the following:

  - A denial of service (DoS) vulnerability exists in the VPN tunneling features of Cisco SD-WAN Software due
    to insufficient handling of malformed packets. An unauthenticated, remote attacker can exploit this, by
    sending crafted packets to an affected device, to cause the device to reboot, resulting in a DoS condition
    of the affected system. (CVE-2021-1241)

  - A denial of service (DoS) vulnerability exists in the IPSec tunnel management of Cisco SD-WAN Software due
    to the bounds checking in the forwarding plane of the IPSec tunnel management functionality. An unauthenticated,
    remote attacker can exploit this, by sending crafted IPv4 or IPv6 packets to the affected device, to cause
    a DoS condition. (CVE-2021-1273)

  - A denial of service (DoS) vulnerability exists in the UDP connection response of Cisco SD-WAN Software due
    to the presence of a null dereference in vDaemon. An unauthenticated, remote attacker can exploit this, by
    sending crafted traffic to an affected device, to cause a DoS condition. (CVE-2021-1274)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-dosmulti-48jJuEUP
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05f6f0f0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq20708");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt11522");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt11523");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt11530");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28409");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu31763");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvq20708, CSCvt11522, CSCvt11523, CSCvt11530,
CSCvu28409, and CSCvu31763.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1241");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20, 119, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

vuln_ranges = [
  { 'min_ver':'0',    'fix_ver':'18.4.6' },
  { 'min_ver':'19.2', 'fix_ver':'20.1.2' },
  { 'min_ver':'20.3', 'fix_ver':'20.3.1' },
  { 'min_ver':'20.4', 'fix_ver':'20.4.1' }
];

# 18.4.302 and 18.4.303 appear to be between 18.4.5
# 20.1.12 is between 20.1.1 and 20.1.2
version_list=make_list(
  '18.4.302',
  '18.4.303',
  '20.1.12'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq20708, CSCvt11522, CSCvt11523, CSCvt11530, CSCvu28409, CSCvu31763',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);
