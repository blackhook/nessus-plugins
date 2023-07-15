#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159306);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id("CVE-2022-22948");
  script_xref(name:"IAVA", value:"2022-A-0127-S");
  script_xref(name:"CEA-ID", value:"CEA-2022-0011");

  script_name(english:"VMware vCenter Server 6.5 / 6.7 / 7.0 Information Disclosure (VMSA-2022-0009)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is 6.5 prior to 6.5 U3r, 6.7 prior to 6.7 U3p, or
7.0 prior to 7.0 U3d. It is, therefore, affected by an information disclosure vulnerability due to improper permission
of files. A malicious actor with non-administrative access to the vCenter Server may exploit this issue to gain access
to sensitive information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version   
number. Nessus has also not tested for the presence of a workaround.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0009.html");
  script_set_attribute(attribute:"see_also", value:"https://www.pentera.io/blog/information-disclosure-in-vmware-vcenter/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server 6.5 U3r, 6.7 U3p, or 7.0 U3d or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22948");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vcenter_detect.nbin");
  script_require_keys("Host/VMware/vCenter", "Host/VMware/version", "Host/VMware/release");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::vmware_vcenter::get_app_info();

# audit out if we're on 6.5 or 6.7 since only the Virtual Appliance version is vuln, while the Windows version isn't
# affected, and we can't tell the difference
if (app_info.version =~ "^6\.[57]\." && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app_info.app, app_info.display_version, app_info.port);

var constraints = [
  { 'min_version' : '6.5', 'fixed_version' : '6.5.18711281', 'fixed_display' : '6.5 U3r' },
  { 'min_version' : '6.7', 'fixed_version' : '6.7.18831049', 'fixed_display' : '6.7 U3p' },
  { 'min_version' : '7.0', 'fixed_version' : '7.0.19480866', 'fixed_display' : '7.0 U3d' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
