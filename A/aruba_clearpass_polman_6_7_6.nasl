#
# (C) Tenable Network Security, Inc
#

include('compat.inc');

if (description)
{
  script_id(139002);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/29");

  script_cve_id(
    "CVE-2018-7063",
    "CVE-2018-7065",
    "CVE-2018-7066",
    "CVE-2018-7067",
    "CVE-2018-7079"
  );
  script_bugtraq_id(106169);
  script_xref(name:"IAVA", value:"2018-A-0410-S");

  script_name(english:"Aruba ClearPass Policy Manager <= 6.6.10 / 6.7.x < 6.7.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Aruba ClearPass Policy Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Aruba ClearPass Policy Manager installed on the remote 
host is equal or prior to 6.6.10, or 6.7.x prior to 6.7.6. It is, therefore, 
affected by multiple vulnerabilities:

  - An XML external entity (XXE) vulnerability exists due to an 
    incorrectly configured XML parser accepting XML external entities 
    from disabled admin accounts. A remote attacker with knowledge of
    these accounts could exploit this vulnerability via specially crafted 
    XML data, to perform read/write operations. (CVE-2018-7063)

  - A SQL injection (SQLi) vulnerability exists due to improper 
    validation of user-supplied input. An authenticated, remote 
    attacker can exploit this to gain access to 'appadmin' credentials,
    which could lead to complete system compromise. (CVE-2018-7065)

  - A remote command execution vulnerability exists in devices
    linked via the OnConnect feature due to a defect in the API. 
    An unauthenticated, remote attacker can exploit this to bypass 
    authentication and execute arbitrary commands on the linked
    devices (CVE-2018-7066)

  - An authentication bypass vulnerability exists in the ClearPass
    administrative network interface's API. A remote unauthenticated
    attacker could exploit this vulnerability to bypass authentication,
    leading to complete compromise. (CVE-2018-7067)

  - An authentication bypass vulnerability exists in ClearPass Guest
    administrative operations due to improper access controls.
    A remote, authenticated attacker could exploit this vulnerability
    to view, modify or delete guest users, regardless of privilege level.
    (CVE-2018-7079)

Note: Nessus is unable to check for the presence of applied hotfixes in this product. Consequently, customers running 
version 6.6.10.x will only be flagged for these vulnerabilities when scan accuracy is set to show potential false 
alarms.");
  script_set_attribute(attribute:"see_also", value:"https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2018-007.txt");
  # https://asp.arubanetworks.com/downloads/software/RmlsZTo1NWVlY2QzZS1iYTg4LTExZTgtOGI4Zi0xZjVhMGUxNWQ3Yzk%3D
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a675aa80");
  # https://asp.arubanetworks.com/downloads/software/RmlsZTpjOTNkYzhiMi1lMmM5LTExZTgtOWEwZC1kZmEyZjA1ZWM4MmY%3D
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6b29b9b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.6.10 and install vendor supplied hotfix, or upgrade to 6.7.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7066");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:arubanetworks:clearpass");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("aruba_clearpass_polman_detect.nbin");
  script_require_keys("Host/Aruba_Clearpass_Policy_Manager/version");

  exit(0);
}

include('vcf.inc');

version_kb = 'Host/Aruba_Clearpass_Policy_Manager/version';
ver = get_kb_item_or_exit(version_kb);

# if < 6.6.10 we can just go through and call it vuln
# since they need to upgrade to 6.6.10 before installing hotfix
if(ver =~ "^6\.6\.10($|[^0-9])" && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'Aruba ClearPass Policy Manager', ver);


app_info = vcf::get_app_info(app:'Aruba ClearPass Policy Manager', port:0, kb_ver:version_kb);  

# calling 6.6.11 fixed because ver <= 6.6.10.abcxyz are vuln
# until we know if hotfix changes minor ver / what that ver would be
# this is effectively the same as setting a max of 6.6.10.9999999 but cleaner.
constraints = [
  { 'fixed_version' : '6.6.11', 'fixed_display': 'Upgrade to 6.6.10 and apply hotfix or upgrade to 6.7.6'},
  { 'min_version' : '6.7.0', 'fixed_version' : '6.7.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);