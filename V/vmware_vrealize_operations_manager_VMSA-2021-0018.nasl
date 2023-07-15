#%NASL_MIN_LEVEL 70300
# (C) Tenable Network Security, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152873);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-22022",
    "CVE-2021-22023",
    "CVE-2021-22024",
    "CVE-2021-22025",
    "CVE-2021-22026",
    "CVE-2021-22027"
  );
  script_xref(name:"VMSA", value:"2021-0018");
  script_xref(name:"IAVA", value:"2021-A-0399");

  script_name(english:"VMware vRealize Operations Manager 7.5.x / 8.x Multiple Vulnerabilities (VMSA-2021-0018)");

  script_set_attribute(attribute:"synopsis", value:
"VMware vRealize Operations running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vRealize Operations (vROps) Manager running on the remote web server is 7.5.x prior to
7.5.0.18528913, 8.0.0 prior to 8.0.1.18442173, or 8.1.0 prior to 8.1.1.18442224 or 8.2.0 prior to 8.2.0.18439239 or
8.3.0 prior to 8.3.0.18439213 or 8.4.0 prior to 8.4.0.18456797. It is, therefore, affected by a multiple vulnerabilities. 

  - The vRealize Operations Manager API contains a broken access control vulnerability leading to unauthenticated API
    access. (CVE-2021-22025)

  - The vRealize Operations Manager API contains an arbitrary log-file read vulnerability. (CVE-2021-22024)

  - The vRealize Operations Manager API contains a Server Side Request Forgery in multiple end points. (CVE-2021-22026,
    CVE-2021-22027)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2021-0018.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vRealize Operations Manager version
7.5.0.18528913, 8.0.1.18442173, 8.1.1.18442224, 8.2.0.18439239, 8.3.0.18439213, 8.4.0.18456797 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22023");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-22027");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_operations");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'min_version':'7.5.0', 'fixed_version':'7.5.0.18528913'},
  {'min_version':'8.0.0', 'fixed_version':'8.0.1.18442173'}, # For 8.0.0, 8.0.1
  {'min_version':'8.1.0', 'fixed_version':'8.1.1.18442224'}, # For 8.1.0, 8.1.1
  {'min_version':'8.2.0', 'fixed_version':'8.2.0.18439239'},
  {'min_version':'8.3.0', 'fixed_version':'8.3.0.18439213'},
  {'min_version':'8.4.0', 'fixed_version':'8.4.0.18456797'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
