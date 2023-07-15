##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(134975);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2019-11634");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Citrix Workspace App and Receiver App for Windows Remote Code Execution Vulnerability (CTX251986)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Workspace installed on the remote host is affected by a remote code execution vulnerability due to 
incorrect access control. An unauthenticated, remote attacker can exploit 
this to bypass authentication and execute arbitrary commands on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX251986");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix Workspace app to version 1904 or later and Receiver for Windows to LTSR 4.9 CU6 version 4.9.6001");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11634");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:workspace");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_workspace_win_installed.nbin");
  script_require_keys("installed_sw/Citrix Workspace");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Citrix Workspace');

var constraints = [{ 'fixed_version' : '19.0.4.0' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
