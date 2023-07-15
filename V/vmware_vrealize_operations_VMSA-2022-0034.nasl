#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169226);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/06");

  script_cve_id("CVE-2022-31707", "CVE-2022-31708");
  script_xref(name:"VMSA", value:"2022-0034");
  script_xref(name:"IAVA", value:"2023-A-0002");

  script_name(english:"VMware vRealize Operations 8.x < 8.6 Hot Fix 8, 8.10.x < 8.10.1 Multiple Vulnerabilities (VMSA-2022-0034)");

  script_set_attribute(attribute:"synopsis", value:
"VMware vRealize Operations running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vRealize Operations (vROps) running on the remote host is 8.x prior to 8.6 Hot Fix 8 or 8.10.x
prior to 8.10.1. It is, therefore, affected by a multiple vulnerabilities:

 - A privilege escalation vulnerability exists. An authenticated, remote attacker with administrative privileges
   can exploit this, to gain root access to the system. (CVE-2022-31707)

 - A broken access control vulnerability exists. An authenticated, remote attacker with administrative privileges
   can exploit this, to read sensitive information from the system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0034.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vRealize Operations Manager version 8.6 Hot Fix 8, 8.10.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31707");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_operations");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  {'min_version':'8.6.0', 'fixed_version':'8.6.4.20823815'},
  {'min_version':'8.10.0', 'fixed_version':'8.10.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
