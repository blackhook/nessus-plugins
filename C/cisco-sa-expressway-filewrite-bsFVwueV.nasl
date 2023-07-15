##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161604);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/11");

  script_cve_id("CVE-2022-20806", "CVE-2022-20807", "CVE-2022-20809");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz71486");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa25061");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa25106");
  script_xref(name:"CISCO-SA", value:"cisco-sa-expressway-filewrite-bsFVwueV");
  script_xref(name:"IAVA", value:"2022-A-0218-S");

  script_name(english:"Cisco Expressway Series / TelePresence VCS Multiple Vulnerabilities (cisco-sa-expressway-filewrite-bsFVwueV)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities in the API and web-based management interfaces of Cisco Expressway Series and Cisco
TelePresence Video Communication Server (VCS) could allow an authenticated, remote attacker to write files or
disclose sensitive information on an affected device, as follows:

  - An authenticated, remote attacker with read write privileges can exploit a vulnerability in the cluster
    database API in order to disclose sensitive information and cause a partial denial of service.
    (CVE-2022-20806)

  - An authenticated, remote attacker with read write privileges can exploit a vulnerability in the
    file-parsing logic in order to disclose sensitive information. (CVE-2022-20807)

  - An authenticated, remote attacker can exploit a vulnerability in the logging component in order to
    disclose sensitive information. (CVE-2022-20809)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-expressway-filewrite-bsFVwueV
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0295c806");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz71486");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa25061");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa25106");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz71486, CSCwa25061, CSCwa25106");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20806");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(73, 532, 611);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/27");

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
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvz71486, CSCwa25061, CSCwa25106',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
