#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105486);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/02");

  script_cve_id(
    "CVE-2017-4940",
    "CVE-2017-4941",
    "CVE-2017-5715",
    "CVE-2017-5753"
  );
  script_bugtraq_id(
    102238,
    102241,
    102371,
    102376
  );
  script_xref(name:"VMSA", value:"2017-0021");
  script_xref(name:"IAVA", value:"2018-A-0020");
  script_xref(name:"VMSA", value:"2018-0002");

  script_name(english:"ESXi 5.5 / 6.0 / 6.5 / Multiple Vulnerabilities (VMSA-2017-0021) (VMSA-2018-0002) (Spectre) (remote check)");
  script_summary(english:"Checks the ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is version 5.5, 6.0, or 6.5 and is
missing a security patch. It is, therefore, affected by multiple
vulnerabilities that can allow code execution in a virtual machine
via the authenticated VNC session as well as cause information disclosure from one
virtual machine to another virtual machine on the same host.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2017-0021.html");
  script_set_attribute(attribute:"see_also", value:"https://www.talosintelligence.com/vulnerability_reports/TALOS-2017-0369");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/us/security/advisories/VMSA-2018-0002.html");
  script_set_attribute(attribute:"see_also", value:"https://meltdownattack.com/");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4941");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release", "Host/VMware/vsphere");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

fixes = make_array(
  '5.5', '6480324',
  '6.0', '6921384',
  '6.5', '7388607'
);

security_only_patches = make_array(
  '5.5', '6480267',
  '6.0', '6856897',
  '6.5', '7273056'
);

rel = get_kb_item_or_exit("Host/VMware/release");
if ("ESXi" >!< rel) audit(AUDIT_OS_NOT, "ESXi");

ver = get_kb_item_or_exit("Host/VMware/version");
port = get_kb_item_or_exit("Host/VMware/vsphere");

match = pregmatch(pattern:"^ESXi? ([0-9]+\.[0-9]+).*$", string:ver);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, "VMware ESXi", "5.5 / 6.0 / 6.5");
ver = match[1];

if (ver != '5.5' && ver != '6.0' && ver != '6.5')
  audit(AUDIT_OS_NOT, "ESXi 5.5 / 6.0 / 6.5");

fixed_build = fixes[ver];
security_only_patch = security_only_patches[ver];

if (empty_or_null(fixed_build)) audit(AUDIT_VER_FORMAT, ver);

match = pregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, "VMware ESXi", "5.5 / 6.0 / 6.5");

build = int(match[1]);

if (build < fixed_build && build != security_only_patch)
{
  if (!isnull(security_only_patch))
    fixed_build += ' / ' + security_only_patch + ' (security-only fix)';

  report = '\n  ESXi version    : ' + ver +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fixed_build +
           '\n';

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report, xss:TRUE);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware ESXi", ver + " build " + build);
