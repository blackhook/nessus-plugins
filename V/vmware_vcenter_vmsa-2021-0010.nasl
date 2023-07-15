#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149902);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-21985", "CVE-2021-21986");
  script_xref(name:"IAVA", value:"2021-A-0254");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0027");

  script_name(english:"VMware vCenter Server 6.5 / 6.7 / 7.0 Multiple Vulnerabilities (VMSA-2021-0010)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is 6.5 prior to 6.5 U3p, 6.7 prior to 6.7 U3n or 7.0
prior to 7.0 U2b. It is, therefore, affected by multiple vulnerabilities:

  - The vSphere Client (HTML5) contains a remote code execution vulnerability due to lack of input validation in the
    Virtual SAN Health Check plug-in which is enabled by default in vCenter Server. A malicious actor with network
    access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying
    operating system that hosts vCenter Server. (CVE-2021-21985)

  - The vSphere Client (HTML5) contains a vulnerability in a vSphere authentication mechanism for the Virtual SAN
    Health Check, Site Recovery, vSphere Lifecycle Manager, and VMware Cloud Director Availability plug-ins. A
    malicious actor with network access to port 443 on vCenter Server may perform actions allowed by the impacted
    plug-ins without authentication. (CVE-2021-21986)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number. Nessus has also not tested for the presence of a workaround.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2021-0010.html");
  script_set_attribute(attribute:"see_also", value:"https://blogs.vmware.com/vsphere/2021/05/vmsa-2021-0010.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server 6.5 U3p, 6.7 U3n, 7.0 U2b or later or apply the workaround mentioned in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21986");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VMware vCenter Server Virtual SAN Health Check Plugin RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vcenter_detect.nbin");
  script_require_keys("Host/VMware/vCenter", "Host/VMware/version", "Host/VMware/release");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::vmware_vcenter::get_app_info();

var constraints = [
  { 'min_version' : '6.5', 'fixed_version' : '6.5.17994927', 'fixed_display' : '6.5 U3p' },
  { 'min_version' : '6.7', 'fixed_version' : '6.7.17713311', 'fixed_display' : '6.7 U3n' },
  { 'min_version' : '7.0', 'fixed_version' : '7.0.17958471', 'fixed_display' : '7.0 U2b' },
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
