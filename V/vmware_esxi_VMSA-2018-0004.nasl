#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105782);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/02");

  script_cve_id("CVE-2017-5715");
  script_bugtraq_id(102376);
  script_xref(name:"VMSA", value:"2018-0004");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"ESXi 5.5 / 6.0 / 6.5 / Hypervisor-Assisted Guest Remediation for Speculative Execution (VMSA-2018-0004) (Spectre) (remote check)");
  script_summary(english:"Checks the ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is missing a security patch 
which enables hardware support for branch target mitigation.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is version 5.5, 6.0, or 6.5 and is
missing a security patch. It is, therefore, missing security
updates that add hypervisor-assisted guest remediation for a
speculative execution vulnerability (CVE-2017-5715). These updates
will allow guest operating systems to use hardware support for
branch target mitigation and will require guest OS security updates
as detailed in VMware Knowledge Base article 52085.

Note that hypervisor-specific remediation's for this vulnerability
were released as part of VMSA-2018-0002.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/us/security/advisories/VMSA-2018-0004.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/52085");
  script_set_attribute(attribute:"see_also", value:"https://spectreattack.com/");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5715");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release", "Host/VMware/vsphere");

  exit(0);
}

# Temp disable
exit(1, 'Temporarily disabled per VMware KB 52345.');

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

fixes = make_array(
  '5.5', '7504623',
  '6.0', '7504637',
  '6.5', '7526125'
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

if (empty_or_null(fixed_build)) audit(AUDIT_VER_FORMAT, ver);

match = pregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, "VMware ESXi", "5.5 / 6.0 / 6.5");

build = int(match[1]);

if (build < fixed_build)
{
  report = '\n  ESXi version    : ' + ver +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fixed_build +
           '\n';

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware ESXi", ver + " build " + build);
