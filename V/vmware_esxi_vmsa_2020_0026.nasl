#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(143221);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id("CVE-2020-4004", "CVE-2020-4005");
  script_xref(name:"VMSA", value:"2020-0026");
  script_xref(name:"IAVA", value:"2020-A-0544");

  script_name(english:"ESXi 6.5 / 6.7 / 7.0 Multiple Vulnerabilities (VMSA-2020-0026)");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is missing a security patch and is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote VMware ESXi host is version 6.5, 6.7 or 7.0 and is affected
by multiple vulnerabilities. 

  - A use-after-free error exists in the XHCI USB controller. An unauthenticated, local attacker with local
    administrative privileges on a virtual machine can exploit this, to execute code as the virtual machine's
    VMX process running on the host. (CVE-2020-4004)

  - A privilege escalation vulnerability exists in ESXi due to how certain system calls are managed. An
    authenticated, local attacker with privileges within the VPM process can exploit this, when chained with
    CVE-2020-4004, to obtain escalated privileges. (CVE-2020-4005)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2020-0026.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4005");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-4004");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");

  exit(0);
}

fixes = make_array(
  '6.5', '17167537',
  '6.7', '17167734',
  '7.0', '17168206'
);

rel = get_kb_item_or_exit('Host/VMware/release');
if ('ESXi' >!< rel) audit(AUDIT_OS_NOT, 'ESXi');

ver = get_kb_item_or_exit('Host/VMware/version');
port  = get_kb_item_or_exit('Host/VMware/vsphere');

match = pregmatch(pattern:"^ESXi? ([0-9]+\.[0-9]+).*$", string:ver);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, 'VMware ESXi', '6.5 / 6.7 / 7.0');
ver = match[1];

if (ver !~ "^(7\.0|6\.(5|7))$") audit(AUDIT_OS_NOT, 'ESXi 6.5 / 6.7 / 7.0');

fixed_build = int(fixes[ver]);

if (empty_or_null(fixed_build)) audit(AUDIT_VER_FORMAT, ver);

match = pregmatch(pattern:"^VMware ESXi.*build-([0-9]+)$", string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, 'VMware ESXi', '6.5 / 6.7 / 7.0');

build = int(match[1]);

if (build >= fixed_build) audit(AUDIT_INST_VER_NOT_VULN, 'VMware ESXi', ver + ' build ' + build);

report = '\n  ESXi version    : ' + ver +
         '\n  Installed build : ' + build +
         '\n  Fixed build     : ' + fixed_build +
         '\n';

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);

