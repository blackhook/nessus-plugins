#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(163486);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2022-22972", "CVE-2022-22973");
  script_xref(name:"VMSA", value:"2022-0014");
  script_xref(name:"CEA-ID", value:"CEA-2022-0020");

  script_name(english:"VMware Workspace One Access / VMware Identity Manager Multiple Vulnerabilities (VMSA-2022-0014)");

  script_set_attribute(attribute:"synopsis", value:
"An identity store broker application running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The VMware Workspace One Access (formerly VMware Identity Manager) application running on the remote host is affected
by the following vulnerabilities:
  - An Authentication Bypass Vulnerability affecting local domain users. A malicious actor with network access to the UI
    may be able to obtain administrative access without the need to authenticate. (CVE-2022-22972)
  - A Local Privilege Escalation Vulnerability. A malicious actor with local access can escalate privileges to 'root'.
    (CVE-2022-22973)
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0014.html");
  script_set_attribute(attribute:"see_also", value:"https://core.vmware.com/vmsa-2022-0014-questions-answers-faq");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/88438");
  script_set_attribute(attribute:"solution", value:
"Apply the HW-156875 hotfix to VMware Workspace One Access / VMware Identity Manager as per the VMSA-2022-0014 advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22972");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workspace_one_access");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:identity_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workspace_one_access_web_detect.nbin");
  script_require_keys("installed_sw/VMware Workspace ONE Access");

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

var app = 'VMware Workspace ONE Access';

get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:80);

var app_info = vcf::vmware_workspace_one_access::get_app_info(port:port);

# 3.3.[3456] don't have fixed builds, so audit out unless we are doing a paranoid scan
if (app_info.version =~ "3\.3\.[3456]\."  && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app, app_info.version);

var constraints = [
  { 'min_version':'3.3.3.0.0', 'fixed_version':'3.3.7.0.0', 'fixed_display':'Refer to vendor advisory and apply patch HW-156875.' },
  # Build numbers for HW-156875 are not available in the advisory
  # Using build numbers from the the previous HF as max_version; https://kb.vmware.com/s/article/88099
  { 'min_version':'20.10.0.0', 'max_version':'20.10.0.0.19540061', 'fixed_display':'20.10.0.0 with HW-156875' },
  { 'min_version':'20.10.0.1', 'max_version':'20.10.0.1.19540061', 'fixed_display':'20.10.0.1 with HW-156875' },
  { 'min_version':'21.08.0.0', 'max_version':'21.08.0.0.19539711', 'fixed_display':'21.08.0.0 with HW-156875' },
  { 'min_version':'21.08.0.1', 'max_version':'21.08.0.1.19539711', 'fixed_display':'21.08.0.1 with HW-156875' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);