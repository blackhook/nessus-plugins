#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168746);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/22");

  script_cve_id("CVE-2022-31697", "CVE-2022-31698");
  script_xref(name:"VMSA", value:"2022-0030");
  script_xref(name:"IAVA", value:"2022-A-0513");

  script_name(english:"VMware vCenter Server 6.5 < 6.5 U3u / 6.7 < 6.7.0 U3s / 7.0 < 7.0 U3i  Multiple Vulnerabilities (VMSA-2022-0030)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is affected by multiple vulnerabilities, as follows:

  - An information disclosure vulnerability due to plaintext logging of credentials. (CVE-2022-31697)

  - A denial of service (DoS) vulnerability in the content library service. (CVE-2022-31698)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number. Nessus has also not tested for the presence of a workaround.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0030.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server 6.5 U3u, 6.7.0 U3s, 7.0 U3i or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31697");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vcenter_detect.nbin");
  script_require_keys("Host/VMware/vCenter", "Host/VMware/version", "Host/VMware/release");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::vmware_vcenter::get_app_info();

var constraints = [
  { 'min_version' : '6.5', 'fixed_version' : '6.5.20510539', 'fixed_display' : '6.5 U3u' },
  { 'min_version' : '6.7', 'fixed_version' : '6.7.20504362', 'fixed_display' : '6.7.0 U3s' },
  { 'min_version' : '7.0', 'fixed_version' : '7.0.20845200', 'fixed_display' : '7.0 U3i' },
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
