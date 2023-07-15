#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174746);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/26");

  script_cve_id("CVE-2023-0662", "CVE-2023-0568");

  script_name(english:"Tenable SecurityCenter 5.22.0 / 5.23.1 / 6.0.0 Multiple Vulnerabilities (TNS-2023-18)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter application installed on the remote host is 
running 5.22.0 or 5.23.1 or 6.0.0 and and is therefore affected by multiple vulnerabilities in PHP prior to 
version 8.0.28 / 8.1.16 / 8.2.3:

    - In PHP 8.0.X before 8.0.28, 8.1.X before 8.1.16 and 8.2.X before 8.2.3, excessive number of parts in HTTP 
      form upload can cause high resource consumption and excessive number of log entries. This can cause denial 
      of service on the affected server by exhausting CPU resources or disk space. (CVE-2023-0662)

    - In PHP 8.0.X before 8.0.28, 8.1.X before 8.1.16 and 8.2.X before 8.2.3, core path resolution function 
      allocate buffer one byte too small. When resolving paths with lengths close to system MAXPATHLEN setting, 
      this may lead to the byte after the allocated buffer being overwritten with NUL value, which might lead to 
      unauthorized data access or modification. (CVE-2023-0568)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2023-18");
  # https://docs.tenable.com/releasenotes/Content/tenablesc/tenablesc2023.htm#Tenable.sc-6.1.0-(2023-03-22)
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c45a331");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0568");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_ports("installed_sw/Tenable SecurityCenter");

  exit(0);
}

include('vcf_extras.inc');

var patches = make_list('SC-202304.1');
var app_info = vcf::tenable_sc::get_app_info();

vcf::tenable_sc::check_for_patch(app_info:app_info, patches:patches);

var constraints = [
    { 'min_version' : '5.22.0', 'max_version': '5.22.0', 'fixed_display' : 'Apply Patch SC-202304.1'},
    { 'min_version' : '5.23.1', 'max_version': '5.23.1', 'fixed_display' : 'Apply Patch SC-202304.1'},
    { 'min_version' : '6.0.0',  'max_version': '6.0.0',  'fixed_display' : 'Apply Patch SC-202304.1'},
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
