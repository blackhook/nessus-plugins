#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159257);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id("CVE-2017-4902", "CVE-2017-4903");
  script_xref(name:"VMSA", value:"2017-0006");

  script_name(english:"ESXi 5.5 < Build 5230635 Multiple Vulnerabilities (VMSA-2017-0006) (remote check) (PCI-DSS check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.5 host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the remote VMware ESXi 5.5 host is prior to build 5230635. It is, therefore, affected by multiple
vulnerabilities:

  - VMware ESXi 5.5 without patch ESXi550-201703401-SG has a Heap Buffer Overflow in SVGA. This issue may
    allow a guest to execute code on the host. (CVE-2017-4902)

  - VMware ESXi 5.5 without patch ESXi550-201703401-SG has an uninitialized stack memory usage in SVGA. This
    issue may allow a guest to execute code on the host. (CVE-2017-4903)
    
Note that Nessus has not tested for these issues but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2017-0006.html");
  script_set_attribute(attribute:"solution", value:
"Apply patch ESXi550-201703401-SG according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4903");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release", "Settings/PCI_DSS");

  exit(0);
}

var ver = get_kb_item_or_exit('Host/VMware/version');
var rel = get_kb_item_or_exit('Host/VMware/release');

if ('ESXi' >!< rel) audit(AUDIT_OS_NOT, 'ESXi');
if ('VMware ESXi 5.5' >!< rel) audit(AUDIT_OS_NOT, 'ESXi 5.5');

var match = pregmatch(pattern:"^VMware ESXi.*build-([0-9]+)$", string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, 'VMware ESXi', '5.5');

# PCI only
if (!get_kb_item('Settings/PCI_DSS')) audit(AUDIT_PCI);

var build = int(match[1]);
var fixed_build = 5230635;

if (build < fixed_build)
{
  var report = '\n  ESXi version    : ' + ver +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fixed_build +
           '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'VMware ESXi', ver - 'ESXi ' + ' build ' + build);
