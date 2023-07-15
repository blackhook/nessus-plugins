#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152534);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/13");

  script_cve_id("CVE-2021-22002", "CVE-2021-22003");
  script_xref(name:"VMSA", value:"2021-0016");
  script_xref(name:"IAVA", value:"2021-A-0370");

  script_name(english:"VMware Workspace One Access / VMware Identity Manager Multiple Vulnerabilities (VMSA-2021-0016)");

  script_set_attribute(attribute:"synopsis", value:
"An identity store broker application running on the remote host is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The VMware Workspace One Access (formerly VMware Identity Manager) application running on the remote host is affected
by the following vulnerabilities:

  - A security bypass vulnerability exists in due to improper validation of host headers. An unauthenticated,
    remote attacker can exploit this, via a crafted request with custom host headers, to bypass access
    restrictions to /cfg web app and other diagnostic endpoints. (CVE-2021-22002)

  - An information disclosure vulnerability exists in due to a login interface on port 7443. An
    unauthenticated, remote attacker can exploit this, via brute force, to potentially access the service.
    (CVE-2021-22003)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2021-0016.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/85254");
  script_set_attribute(attribute:"solution", value:
"Apply the HW-137959 hotfix to VMware Workspace One Access / VMware Identity Manager as per the VMSA-2021-0016 advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22002");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:workspace_one_access");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:identity_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workspace_one_access_web_detect.nbin");
  script_require_keys("installed_sw/VMware Workspace ONE Access");

  exit(0);
}

include('audit.inc');
include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

var app = 'VMware Workspace ONE Access';

get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:80);

var app_info = vcf::vmware_workspace_one_access::get_app_info(port:port);

var constraints = [
  { 'min_version':'3.3.2.0.0', 'fixed_version':'3.3.2.0.18380333', 'fixed_display':'3.3.2.0 Build 18380333 (HW-137959)' },
  { 'min_version':'3.3.3.0.0', 'fixed_version':'3.3.3.0.18380315', 'fixed_display':'3.3.3.0 Build 18380315 (HW-137959)' },
  { 'min_version':'3.3.4.0.0', 'fixed_version':'3.3.4.0.18380307', 'fixed_display':'3.3.4.0 Build 18380307 (HW-137959)' },
  { 'min_version':'3.3.5.0.0', 'fixed_version':'3.3.5.0.18380290', 'fixed_display':'3.3.5.0 Build 18380290 (HW-137959)' },

  { 'min_version':'20.01.0.0', 'fixed_version':'20.01.0.0.18379902', 'fixed_display':'20.01.0.0 Build 18379902 (HW-137959)' },
  { 'min_version':'20.10.0.0', 'fixed_version':'20.10.0.0.18379838', 'fixed_display':'20.10.0.0 Build 18379838 (HW-137959)' },
  { 'min_version':'20.10.0.1', 'fixed_version':'20.10.0.1.18379838', 'fixed_display':'20.10.0.1 Build 18379838 (HW-137959)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
