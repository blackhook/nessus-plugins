#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166101);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/15");

  script_cve_id("CVE-2022-31680");
  script_xref(name:"IAVA", value:"2022-A-0402-S");

  script_name(english:"VMware vCenter Server 6.5 < 6.5 U3u RCE (VMSA-2022-0025)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is 6.5 prior to 6.5 U3u. It is, therefore, affected
by a remote code execution vulnerability due to unsafe deserialization. A remote attacker with admin privileges on the
affected server can exploit this vulnerability to execute arbitrary code on the underlying operation system that hosts
the vCenter Server.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number. Nessus has also not tested for the presence of a workaround.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-025.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server 6.5 U3u or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31680");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '6.5', 'fixed_version' : '6.5.20510539', 'fixed_display' : '6.5 U3u' },
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
