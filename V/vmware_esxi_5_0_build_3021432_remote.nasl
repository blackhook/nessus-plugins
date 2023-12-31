#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86945);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2015-1047", "CVE-2015-2342", "CVE-2015-5177");
  script_bugtraq_id(76635, 76930, 76932);
  script_xref(name:"VMSA", value:"2015-0007");
  script_xref(name:"ZDI", value:"ZDI-15-455");

  script_name(english:"VMware ESXi 5.0 < Build 3021432 OpenSLP RCE (VMSA-2015-0007)");
  script_summary(english:"Checks the ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is version 5.0 prior to build 3021432. It
is, therefore, affected by a remote code execution vulnerability due
to a double-free error in the SLPDProcessMessage() function in
OpenSLP. An unauthenticated, remote attacker can exploit this, via a
crafted package, to execute arbitrary code or cause a denial of
service condition.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2015-0007.html");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-15-455/");
  script_set_attribute(attribute:"solution", value:
"Apply patch ESXi500-201510101-SG for ESXi 5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2342");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java JMX Server Insecure Configuration Java Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/VMware/version");
rel = get_kb_item_or_exit("Host/VMware/release");

if ("ESXi" >!< rel) audit(AUDIT_OS_NOT, "ESXi");
if ("VMware ESXi 5.0" >!< rel) audit(AUDIT_OS_NOT, "ESXi 5.0");

match = pregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) exit(1, 'Failed to extract the ESXi build number.');

build = int(match[1]);
fixed_build = 3021432;

if (build < fixed_build)
{
  if (report_verbosity > 0)
  {
    report = '\n  ESXi version    : ' + ver +
             '\n  Installed build : ' + build +
             '\n  Fixed build     : ' + fixed_build +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware ESXi", ver - "ESXi " + " build " + build);
