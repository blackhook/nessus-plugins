#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177742);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id(
    "CVE-2023-20892",
    "CVE-2023-20893",
    "CVE-2023-20894",
    "CVE-2023-20895",
    "CVE-2023-20896"
  );
  script_xref(name:"IAVA", value:"2023-A-0319");

  script_name(english:"VMware vCenter Server 7.0 < 7.0 U3m / 8.0 < 8.0 U1b Multiple Vulnerabilities (VMSA-2023-0014)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of vCenter Server installed on the remote host is 7.0 prior to 7.0 U3m or 8.0 prior to 8.0 U1b. It is,
therefore, affected by multiple vulnerabilities, as follows:

  - A heap overflow vulnerability due to the usage of uninitialized memory in the implementation of the DCERPC protocol.
  (CVE-2023-20892)

  - A use-after-free vulnerability in the implementation of the DCERPC protocol. (CVE-2023-20893)

  - An out-of-bounds write vulnerability in the implementation of the DCERPC protocol. (CVE-2023-20894)

  - A memory corruption vulnerability in the implementation of the DCERPC protocol. (CVE-2023-20895)

  - An out-of-bounds read vulnerability in the implementation of the DCERPC protocol. (CVE-2023-20896)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2023-0014.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to vCenter Server 7.0 U3m, 8.0 U1b or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20895");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/29");

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

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::vmware_vcenter::get_app_info();

var constraints = [
  { 'min_version' : '7.0', 'fixed_version' : '7.0.21784236', 'fixed_display' : '7.0 U3m' },
  { 'min_version' : '8.0', 'fixed_version' : '8.0.21860503', 'fixed_display' : '8.0 U1b' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
