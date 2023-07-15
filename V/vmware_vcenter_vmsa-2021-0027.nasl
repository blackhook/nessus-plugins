#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155790);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id("CVE-2021-21980", "CVE-2021-22049");
  script_xref(name:"IAVA", value:"2021-A-0563-S");

  script_name(english:"VMware vCenter Server 6.5 / 6.7 Multiple Vulnerabilities (VMSA-2021-0027)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is 6.5 prior to 6.5 U3r or 6.7 prior to 6.7 U3p. It
is, therefore, affected by multiple vulnerabilities:

  - An arbitrary file read vulnerability exists in the vSphere web client. An unauthenticated, remote attacker
    can exploit this, via HTTPS, to gain access to sensitive information. (CVE-2021-21980)

  - A server side request forgery vulnerability exists in the vSAN Web Client plug-in. An unauthenticated,
    remote attacker can exploit this, via HTTPS, to cause the server to access internal services or access
    sites outside of vCenter. (CVE-2021-22049)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version   
number. Nessus has also not tested for the presence of a workaround.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2021-0027.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server 6.5 U3r, 6.7 U3p, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22049");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/02");

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
    { 'min_version' : '6.5', 'fixed_version' : '6.5.18711281', 'fixed_display' : '6.5 U3r' },
    { 'min_version' : '6.7', 'fixed_version' : '6.7.18831016', 'fixed_display' : '6.7 U3p' }
  ];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
