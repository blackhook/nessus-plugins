##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164148);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/26");

  script_cve_id(
    "CVE-2022-31672",
    "CVE-2022-31673",
    "CVE-2022-31674",
    "CVE-2022-31675"
  );
  script_xref(name:"VMSA", value:"2022-0022");
  script_xref(name:"IAVA", value:"2022-A-0326");

  script_name(english:"VMware vRealize Operations 8.x < 8.6.4 Multiple Vulnerabilities (VMSA-2022-0022)");

  script_set_attribute(attribute:"synopsis", value:
"VMware vRealize Operations running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vRealize Operations (vROps) running on the remote host is 8.x prior to 8.6.4. It is, therefore,
affected by a multiple vulnerabilities:

 - A malicious actor with administrative network access can escalate privileges to root. (CVE-2022-31672)

 - A low-privileged malicious actor with network access can create and leak hex dumps, leading to information
   disclosure. Successful exploitation can lead to a remote code execution. (CVE-2022-31673)

 - A low-privileged malicious actor with network access can access log files that lead to information
   disclosure. (CVE-2022-31674)

 - An unauthenticated malicious actor with network access may be able to create a user with administrative
   privileges. (CVE-2022-31675)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2021-0018.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vRealize Operations Manager version 8.6.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31673");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_operations");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'min_version':'8.0.0', 'fixed_version':'8.6.4'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
