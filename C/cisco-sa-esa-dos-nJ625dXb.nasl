#TRUSTED 6fa1e0c4f230ee7eb5f5fd013b196df06b9e94971e9da374ac95d722b8ea422a10288f6f47874b9f2b17fe6ae749c997baa2fc1f72adbe81d248a1ea1b394cd5b5cdfad01f9d606627b969dc791cc63412c5dffacd7f0545961c2211afe51c4059a2a39f5c4a7e5b2d7a377b7566bee398d2273029bf9e615ad48ef2183f45601196257a8328e75f085b5ffb42da4931e8d9a36e99bc38a4a2bb1129fa6f5cdd44ccb4e218dba635de8f07855ef7fa0e43c10751a06e91eb4628b69d29fd1ed95e6b17ecdcae057cebca6e951aa46456af0cae679b8004a9e4505dad2b939a343681ee05e565d20ee7b7f476fc7c57fe2b855a0fb8b2a460d7b0b826a39e4518697c18decf494d18d4c5b7f475853d97ab1dd36972cb904c16ed0b96a41e69d22d5b3283bab1e85ba457d55b30c08dfa04f28458621e54d81be81883d954d90ea813ab6ef2a9f72550843da43d0d2673b4e6c62bee3c4e10babff4226ceec837182999780af460f5ed0a16959e0f3af63db08e20525699fccd574430dbc6f4d5093be48e96c415ee58034423c695bfa7a92b77053581ee12a7cedd357dca0d1eadaffc9ec6857197858f6c852f9ee9b8550354d68d92bafe431173665e8be5c709feddb07b67e5c50ac16e178486cddbc3e39c18b4605995c082ea889092cbdf2b79ee7d72eed3ec7f53ec2fcb116533fd036badbac890bcf9f28a6abf043ed8
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(134444);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/19");

  script_cve_id("CVE-2020-3164");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq96943");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs33296");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs33306");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cont-sec-gui-dos-nJ625dXb");
  script_xref(name:"IAVA", value:"2020-A-0100");

  script_name(english:"Cisco Email Security Appliance (ESA) GUI Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Email Security Appliance (ESA) is affected by a Denial of Service
vulnerability. The vulnerability is due to improper validation of specific HTTP request headers. An attacker could
exploit this vulnerability by sending a malformed HTTP request to an affected device. A successful exploit could
allow the attacker to trigger a prolonged status of high CPU utilization relative to the GUI process(es).

Please see the included Cisco BIDs and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cont-sec-gui-dos-nJ625dXb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bded73ef");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq96943");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs33296");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs33306");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security Advisory
cisco-sa-cont-sec-gui-dos-nJ625dXb.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3164");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

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

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

# Cisco ESA 13.0.0-392 and earlier
var vuln_ranges = [{'min_ver': '0.0', 'fix_ver': '13.0.0.393'}];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvs33296',
  'fix'           , '13.0.0-393',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);