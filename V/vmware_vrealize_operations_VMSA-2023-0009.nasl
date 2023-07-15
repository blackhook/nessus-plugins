#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176070);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id(
    "CVE-2023-20877",
    "CVE-2023-20878",
    "CVE-2023-20879",
    "CVE-2023-20880"
  );
  script_xref(name:"VMSA", value:"2023-0009");
  script_xref(name:"IAVA", value:"2023-A-0257");

  script_name(english:"VMware vRealize Operations Multiple Vulnerabilities (VMSA-2023-0009)");

  script_set_attribute(attribute:"synopsis", value:
"VMware vRealize Operations running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vRealize Operations (vROps) running on the remote host is missing a vendor supplied patch. It is,
therefore, affected by multiple vulnerabilities:

  - VMware Aria Operations contains a privilege escalation vulnerability. An authenticated malicious user with
    ReadOnly privileges can perform code execution leading to privilege escalation. (CVE-2023-20877)

  - VMware Aria Operations contains a deserialization vulnerability. A malicious actor with administrative
    privileges can execute arbitrary commands and disrupt the system. (CVE-2023-20878)

  - VMware Aria Operations contains a Local privilege escalation vulnerability. A malicious actor with
    administrative privileges in the Aria Operations application can gain root access to the underlying
    operating system. (CVE-2023-20879)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2023-0009.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade VMware vRealize Operations Manager to the version outlined in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20877");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_operations");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:aria_operations_for_logs");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vrealize_operations_manager_webui_detect.nbin");
  script_require_keys("installed_sw/vRealize Operations Manager");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'vRealize Operations Manager';
get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

var constraints = [
  # https://kb.vmware.com/s/article/91852
  {'min_version':'8.10.0', 'fixed_version':'8.10.2.21553501', 'fixed_display':'8.10 Hot Fix 4'},
  # https://kb.vmware.com/s/article/91850
  {'min_version':'8.6.0', 'fixed_version':'8.6.4.21711971', 'fixed_display':'8.6 Hot Fix 10'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
