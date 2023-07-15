##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(149062);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/03");

  script_cve_id(
    "CVE-2021-23276",
    "CVE-2021-23277",
    "CVE-2021-23278",
    "CVE-2021-23279",
    "CVE-2021-23280",
    "CVE-2021-23281"
  );
  script_xref(name:"IAVA", value:"2021-A-0203");

  script_name(english:"Eaton Intelligent Power Manager (IPM) < 1.69 Multiple Vulnerabilities (ETN-VA-2021-1000)");

  script_set_attribute(attribute:"synopsis", value:
"A web application development suite installed on the remote Windows
host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Eaton Intelligent Power Manager installed on the remote Windows host is prior to 1.69. It is, 
therefore, affected multiple vulnerabilities:
  
  - Eaton Intelligent Power Manager (IPM) prior to 1.69 is vulnerable to unauthenticated arbitrary file
    delete vulnerability induced due to improper input validation in meta_driver_srv.js class with
    saveDriverData action using invalidated driverID. An attacker can send specially crafted packets to
    delete the files on the system where IPM software is installed (CVE-2021-23279).

  - Eaton Intelligent Power Manager (IPM) prior to 1.69 is vulnerable to authenticated arbitrary file upload
    vulnerability. IPM’s maps_srv.js allows an attacker to upload a malicious NodeJS file using
    uploadBackgroud action. An attacker can upload a malicious code or execute any command using a
    specially crafted packet to exploit the vulnerability (CVE-2021-23280). 

  - Eaton Intelligent Power Manager (IPM) prior to 1.69 is vulnerable to unauthenticated remote code
    execution vulnerability. IPM software does not sanitize the date provided via coverterCheckList action
    in meta_driver_srv.js class. Attackers can send a specially crafted packet to make IPM connect to
    rouge SNMP server and execute attacker-controlled code (CVE-2021-23281). 
 
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://www.eaton.com/content/dam/eaton/company/news-insights/cybersecurity/security-bulletins/eaton-intelligent-power-manager-ipm-vulnerability-advisory.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23783677");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Eaton IPM version 1.69 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23281");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:eaton:intelligent_power_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("eaton_ipm_win_installed.nbin");
  script_require_keys("installed_sw/Eaton Intelligent Power Manager", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit("SMB/Registry/Enumerated");
 
var app_info = vcf::get_app_info(app:"Eaton Intelligent Power Manager");
var constraints = [{'fixed_version' : '1.69'}];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);
