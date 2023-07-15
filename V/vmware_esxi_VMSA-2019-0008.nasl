#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125218);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-12126",
    "CVE-2018-12127",
    "CVE-2018-12130",
    "CVE-2019-11091"
  );
  script_bugtraq_id(108330);
  script_xref(name:"VMSA", value:"2019-0008");
  script_xref(name:"IAVA", value:"2019-A-0167");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");
  script_xref(name:"CEA-ID", value:"CEA-2019-0324");

  script_name(english:"ESXi 6.0 / 6.5 / 6.7 Multiple Vulnerabilities (VMSA-2019-0008)(MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout)(Remote Check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is missing a security patch and is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is version 6.0, 6.5 or 6.7 and is missing a security patch. It is, therefore, missing 
microcode updates to address the following vulnerabilities:

  - Microarchitectural Store Buffer Data Sampling (MSBDS) (CVE-2018-12126)
  - Microarchitectural Load Port Data Sampling (MLPDS) (CVE-2018-12127)
  - Microarchitectural Fill Buffer Data Sampling (MFBDS) (CVE-2018-12130)
  - Microarchitectural Data Sampling Uncacheable Memory (MDSUM) (CVE-2019-11091)

Note virtual machines must be configured with the 3D-acceleration enabled. VMware ESXi defaults to this feature not 
being enabled.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2019-0008.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11091");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release", "Host/VMware/vsphere", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes = make_array(
  '6.0', '13635687',
  '6.5', '13635690',
  '6.7', '13644319'
);

rel = get_kb_item_or_exit('Host/VMware/release');
if ('ESXi' >!< rel) audit(AUDIT_OS_NOT, 'ESXi');

ver = get_kb_item_or_exit('Host/VMware/version');
port = get_kb_item_or_exit('Host/VMware/vsphere');

match = pregmatch(pattern:'^ESXi? ([0-9]+\\.[0-9]+).*$', string:ver);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, 'VMware ESXi', '6.0 / 6.5 / 6.7');
ver = match[1];

if (ver !~ '^6\\.(0|5|7)$') audit(AUDIT_OS_NOT, 'ESXi 6.0 / 6.5 / 6.7');

fixed_build = fixes[ver];

if (empty_or_null(fixed_build)) audit(AUDIT_VER_FORMAT, ver);

match = pregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, 'VMware ESXi', '6.0 / 6.5 / 6.7');

build = int(match[1]);

if (!(build < fixed_build)) audit(AUDIT_INST_VER_NOT_VULN, 'VMware ESXi', ver + ' build ' + build);

report = '\n  ESXi version    : ' + ver +
         '\n  Installed build : ' + build +
         '\n  Fixed build     : ' + fixed_build +
         '\n';

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
