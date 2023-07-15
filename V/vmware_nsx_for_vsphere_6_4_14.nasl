#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(166697);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id("CVE-2021-39144", "CVE-2022-31678");
  script_xref(name:"IAVA", value:"2022-A-0445");
  script_xref(name:"CEA-ID", value:"CEA-2022-0035");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/03/31");

  script_name(english:"VMware NSX for vSphere (NSX-v) < 6.4.14 Multiple Vulnerabilities (VMSA-2022-0027)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware NSX for vSphere (NSX-V) installed on the remote host is prior to 6.4.14. It is,
therefore, affected by multiple vulnerabilities, including:

  - VMware Cloud Foundation contains a remote code execution vulnerability via XStream open source library.
    (CVE-2021-39144)
  
  - VMware Cloud Foundation contains an XML External Entity (XXE) vulnerability. (CVE-2022-31678)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number. Nessus has also not tested for the presence of a workaround.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0027.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/89809");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware NSX for vSphere (NSX-V) 6.4.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39144");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-31678");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VMware NSX Manager XStream unauthenticated RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:vmware:nsx-v");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:vmware:nsx_for_vsphere");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_nsx_for_vsphere_web_detect.nbin");
  script_require_keys("installed_sw/VMware NSX for vSphere (NSX-v)");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'VMware NSX for vSphere (NSX-v)';
get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

var constraints = [
  {'min_version':'6.0.0', 'fixed_version':'6.4.14'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);