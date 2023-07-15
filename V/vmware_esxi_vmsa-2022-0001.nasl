##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(165337);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2021-22045");
  script_xref(name:"VMSA", value:"2022-0001");
  script_xref(name:"IAVA", value:"2022-A-0039");

  script_name(english:"ESXi 6.5 / 6.7 / 7.0 Heap Overflow RCE (VMSA-2022-0001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is missing a security patch and is affected by a heap overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is version 6.5, 6.7 or 7.0 and is affected by a heap overflow vulnerability in CD-ROM
device emulation. A malicious actor with access to a virtual machine with CD-ROM device emulation may be able to exploit
this vulnerability in conjunction with other issues to execute code on the hypervisor from a virtual machine.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0001.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch or workaround as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22045");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release", "Settings/ParanoidReport");

  exit(0);
}

# Not checking workaround https://kb.vmware.com/s/article/87249
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var fixes = make_array(
  '6.5', '18678235', # ESXi650-202110001
  '6.7', '18828794', # ESXi670-202111001
  '7.0', '19193900'  # ESXi 7.0 Update 3c
);

var rel = get_kb_item_or_exit('Host/VMware/release');
if ('ESXi' >!< rel) audit(AUDIT_OS_NOT, 'ESXi');

var ver = get_kb_item_or_exit('Host/VMware/version');
var port  = get_kb_item_or_exit('Host/VMware/vsphere');

var match = pregmatch(pattern:"^ESXi? ([0-9]+\.[0-9]+).*$", string:ver);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, 'VMware ESXi', '6.5 / 6.7 / 7.0');
ver = match[1];

if (ver !~ "^(7\.0|6\.(5|7))$") audit(AUDIT_OS_NOT, 'ESXi 6.5 / 6.7 / 7.0');

var fixed_build = int(fixes[ver]);

if (empty_or_null(fixed_build)) audit(AUDIT_VER_FORMAT, ver);

match = pregmatch(pattern:"^VMware ESXi.*build-([0-9]+)$", string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, 'VMware ESXi', '6.5 / 6.7 / 7.0');

var build = int(match[1]);

if (build >= fixed_build) audit(AUDIT_INST_VER_NOT_VULN, 'VMware ESXi', ver + ' build ' + build);

var report = '\n  ESXi version    : ' + ver +
         '\n  Installed build : ' + build +
         '\n  Fixed build     : ' + fixed_build +
         '\n';

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
