##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163100);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id("CVE-2022-22982");
  script_xref(name:"IAVA", value:"2022-A-0278");

  script_name(english:"VMware vCenter Server 6.5 / 6.7 / 7.0 SSRF (VMSA-2022-0018)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host is affected by a server-side request forgery
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is 6.5 prior to 6.5 U3t, 6.7 prior to 6.7 U3r, or
7.0 prior to 7.0 U3f. It is, therefore, affected by a server-side request forgery (SSRF) vulnerability. A remote
attacker with network access to port 433 can exploit this send a URL request outside of vCenter Server or to an
internal service.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version   
number. Nessus has also not tested for the presence of a workaround.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0018.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server 6.5 U3t, 6.7 U3r, or 7.0 U3f or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22982");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vcenter_detect.nbin");
  script_require_keys("Host/VMware/vCenter", "Host/VMware/version", "Host/VMware/release");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::vmware_vcenter::get_app_info();

var constraints = [
  { 'min_version' : '6.5', 'fixed_version' : '6.5.19757181', 'fixed_display' : '6.5 U3t' },
  { 'min_version' : '6.7', 'fixed_version' : '6.7.19832247', 'fixed_display' : '6.7 U3r' },
  { 'min_version' : '7.0', 'fixed_version' : '7.0.20051473', 'fixed_display' : '7.0 U3f' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
