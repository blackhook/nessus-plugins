#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169513);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/27");

  script_cve_id("CVE-2022-31705");
  script_xref(name:"VMSA", value:"2022-0033");
  script_xref(name:"IAVA", value:"2022-A-0513");

  script_name(english:"VMware ESXi 7.0 / 8.0 Heap Out-of-bounds Write (VMSA-2022-0033)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"VMware ESXi contain a heap out-of-bounds write vulnerability in the USB 2.0 controller (EHCI). 
A malicious actor with local administrative privileges on a virtual machine may exploit this 
issue to execute code as the virtual machine's VMX process running on the host. The exploitation 
is contained within the VMX sandbox. (CVE-2022-31705)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0033.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ESXi 7.0 Build 20841705, 8.0a Build 20842819 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31705");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release", "Host/VMware/vsphere");

  exit(0);
}

var fixes = make_array(
    '7.0', 20841705,
    '8.0', 20842819
);

var fixed_display = make_array(
    '7.0', '7.0U3 ESXi70U3si-20841705',
    '8.0', '8.0 ESXi80a-20842819'
);

var rel = get_kb_item_or_exit('Host/VMware/release');
if ('ESXi' >!< rel) audit(AUDIT_OS_NOT, 'ESXi');

var ver = get_kb_item_or_exit('Host/VMware/version');
var port  = get_kb_item_or_exit('Host/VMware/vsphere');

var match = pregmatch(pattern:"^ESXi? ([0-9]+\.[0-9]+).*$", string:ver);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, 'VMware ESXi', '7.0 / 8.0');
ver = match[1];

if (ver !~ "^(7\.0|8\.0)$") audit(AUDIT_OS_NOT, 'ESXi 7.0 / 8.0');

var fixed_build = fixes[ver];

if (empty_or_null(fixed_build)) audit(AUDIT_VER_FORMAT, ver);

match = pregmatch(pattern:"^VMware ESXi.*build-([0-9]+)$", string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, 'VMware ESXi', '7.0 / 8.0');

var build = int(match[1]);

if (build >= fixed_build) audit(AUDIT_INST_VER_NOT_VULN, 'VMware ESXi', ver + ' build ' + build);

# Not checking workaround https://kb.vmware.com/s/article/76372
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'VMware ESXi');

var report = '\n  ESXi version    : ' + ver +
         '\n  Installed build : ' + build +
         '\n  Fixed build     : ' + fixed_display[ver] +
         '\n';

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
