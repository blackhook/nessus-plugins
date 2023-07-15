#TRUSTED 6a7c55844a4584ac2f5bf892e4d0162fa20c6752c399625212598585d5061b9fcf9b1a9c1dd2a40ac5747d077cc26c01d96b50849eb5871487823c71cbf6c15ee64b8a0197382c7df16c09ab1c6b9ebb3b991f2ae1264ca8b111bb5c81b1512df9bbce152d2c29048182a251f78c0aa643f6c070d07b1acd9f2b4e589bfe3e78bfea41371817b12e77a64641d42147267865d036f3343336e5c53ab99cf427b42eec9e48600ca107c2dcb8501dfd68e2daa52daeb277ca1590c5fada524ce018c605ee48429b7683d492a300fd018aed4bb6c85927faf73f109e7a6ccfc7948cccee4439fac71526d00b7372294a1f8259e8936e47cca5793e21494406f6a564ec59fe0ad44cef72df966e603012be4dfd81c73559db40b31fa7ddb332bcc5000c7a0d05dc0c24b3c3ecd260510af6b8e59567c109605333019c0da3fa178b39fdbb90f7fcce0d768eac4eb608a8a04d1aa8190150164ccf7c148989734ca81f359dde69e66bf28de65a509f54509022411238975989c230537c9f219f52884ab0abad83f440a29a5407224713742117b0b5cad818300a415144569467e8bde52ef3687c14e862fd7afb1194296b354fa632b16b53f00728aaae06852c810aa0475cb0cc701984abca49620b77c3ae1c74404fb131ae3ba6f42e106e681e6aef9cb8952e3b56855de676a5f8ce88902a43bba7e2d56dd70fb26f58706eba2461
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162854);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/11");

  script_cve_id("CVE-2022-20812", "CVE-2022-20813");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa01080");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa01085");
  script_xref(name:"CISCO-SA", value:"cisco-sa-expressway-overwrite-3buqW8LH");
  script_xref(name:"IAVA", value:"2022-A-0218-S");

  script_name(english:"Cisco TelePresence VCS Multiple Vulnerabilities (cisco-sa-expressway-overwrite-3buqW8LH)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco TelePresence Video Communication Server is affected by multiple
vulnerabilities in the API and in the web-based management interface that allow a remote attacker to overwrite
arbitrary files or conduct null byte poisoning attacks on an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-expressway-overwrite-3buqW8LH
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03d2bbb2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa01080");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa01085");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwa01080, CSCwa01085");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20812");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(36, 158);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco TelePresence VCS');
var vuln_ranges = [{ 'min_ver':'0.0', 'fix_ver' : '14.0.7' }];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwa01080, CSCwa01085',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
