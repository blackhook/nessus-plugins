#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158494);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2021-22040",
    "CVE-2021-22041",
    "CVE-2021-22042",
    "CVE-2021-22043",
    "CVE-2021-22050"
  );
  script_xref(name:"IAVA", value:"2022-A-0089");

  script_name(english:"ESXi 6.5 / 6.7 / 7.0 Multiple Vulnerabilities (VMSA-2022-0004)");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is missing a security patch and is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is version 6.5, 6.7 or 7.0 and is affected by multiple vulnerabilities, including the
following:

  - VMware ESXi, Workstation, and Fusion contain a use-after-free vulnerability in the XHCI USB controller. A
    malicious actor with local administrative privileges on a virtual machine may exploit this issue to
    execute code as the virtual machine's VMX process running on the host. (CVE-2021-22040)

  - VMware ESXi, Workstation, and Fusion contain a double-fetch vulnerability in the UHCI USB controller. A
    malicious actor with local administrative privileges on a virtual machine may exploit this issue to
    execute code as the virtual machine's VMX process running on the host. (CVE-2021-22041)

  - VMware ESXi contains an unauthorized access vulnerability due to VMX having access to settingsd
    authorization tickets. A malicious actor with privileges within the VMX process only, may be able to
    access settingsd service running as a high privileged user. (CVE-2021-22042)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0004.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22043");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-22042");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release", "Host/VMware/vsphere");

  exit(0);
}

var fixes = make_array(
  '6.5', 19092475, # ESXi650-202202401-SG
  '6.7', 18828794, # ESXi670-202111101-SG
  '7.0', 19193900  # ESXi70U3c-19193900
);

# Note there are three updates for 7.0 with the update for 7.0 U3 being the lowest build number
#   7.0 U1 - 1e - ESXi70U1e-19324898
#   7.0 U2 - 2e - ESXi70U2e-19290878
#   7.0 U3 - 3c - ESXi70U3c-19193900

# Also note that we are not checking for any workarounds. While there are workarounds for CVE-2021-22041, other CVEs do
# not have workarounds

var rel = get_kb_item_or_exit('Host/VMware/release');
if ('ESXi' >!< rel) audit(AUDIT_OS_NOT, 'ESXi');

var ver = get_kb_item_or_exit('Host/VMware/version');
var port  = get_kb_item_or_exit('Host/VMware/vsphere');

var match = pregmatch(pattern:"^ESXi? ([0-9]+\.[0-9]+).*$", string:ver);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, 'VMware ESXi', '6.5 / 6.7 / 7.0');
ver = match[1];

if (ver !~ "^(7\.0|6\.(5|7))$") audit(AUDIT_OS_NOT, 'ESXi 6.5 / 6.7 / 7.0');

var fixed_build = fixes[ver];

if (empty_or_null(fixed_build)) audit(AUDIT_VER_FORMAT, ver);

match = pregmatch(pattern:"^VMware ESXi.*build-([0-9]+)$", string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, 'VMware ESXi', '6.5 / 6.7 / 7.0');

var build = int(match[1]);

if (build >= fixed_build) audit(AUDIT_INST_VER_NOT_VULN, 'VMware ESXi', ver + ' build ' + build);

# Extra details for 7.0
if (ver == '7.0')
  fixed_build = '7.0U1 19324898 / 7.0U2 19290878 / 7.0U3 19193900';

var report = '\n  ESXi version    : ' + ver +
         '\n  Installed build : ' + build +
         '\n  Fixed build     : ' + fixed_build +
         '\n';

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
