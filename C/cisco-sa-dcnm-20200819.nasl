#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139805);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/31");

  script_cve_id("CVE-2020-3521", "CVE-2020-3538", "CVE-2020-3539");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt86742");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu57876");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28388");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dcnm-file-path-6PKONjHe");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dcnm-pa-trav-bMdfSTTq");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dcnm-authbypass-YVJzqgk2");
  script_xref(name:"IAVA", value:"2020-A-0279");

  script_name(english:"Cisco Data Center Network Manager Multiple Vulnerabilities (Aug 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Data Center Network Manager is affected by multiple vulnerabilities.

  - A vulnerability in a specific REST API of Cisco Data Center Network Manager (DCNM) Software could
    allow an authenticated, remote attacker to conduct directory traversal attacks on an affected device.
    (CVE-2020-3521)

  - A vulnerability in a certain REST API endpoint of Cisco Data Center Network Manager (DCNM) Software
    could allow an authenticated, remote attacker to perform a path traversal attack on an affected
    device. (CVE-2020-3538)

  - A vulnerability in the web-based management interface of Cisco Data Center Network Manager (DCNM)
    could allow an authenticated, remote attacker to view, modify, and delete data without proper
    authorization. (CVE-2020-3539)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dcnm-file-path-6PKONjHe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8aa2e927");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dcnm-pa-trav-bMdfSTTq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?981ac19e");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dcnm-authbypass-YVJzqgk2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eecca8d6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt86742");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu57876");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28388");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID's CSCvt86742, CSCvu57876, CSCvu28388");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3521");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20, 285);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:data_center_network_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_dcnm_installed_win.nasl", "cisco_prime_dcnm_installed_linux.nasl", "cisco_prime_dcnm_web_detect.nasl");
  script_require_keys("installed_sw/Cisco Prime DCNM", "installed_sw/cisco_dcnm_web");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::cisco_dcnm_web::get_app_info();
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'fixed_version' : '11.4.1.0', 'fixed_display' : '11.4(1)' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

