#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103375);
  script_version("3.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-4925");
  script_bugtraq_id(100842);
  script_xref(name:"VMSA", value:"2017-0015");

  script_name(english:"ESXi 5.5 < Build 6480267 RPC NULL Pointer Dereference Vulnerability (VMSA-2017-0015) (remote check)");
  script_summary(english:"Checks the ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.5 host is affected by an RPC NULL
pointer dereference vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the remote VMware ESXi 5.5 host is prior to build
6480267. It is, therefore, affected by a NULL pointer dereference
vulnerability related to handling RPC requests that could allow an
attacker to crash a virtual machine.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2017-0015.html");
  script_set_attribute(attribute:"solution", value:
"Apply patch ESXi550-201709101-SG according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4925");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ("VMware ESXi 5.5" >!< rel) audit(AUDIT_OS_NOT, "ESXi 5.5");

match = pregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, "VMware ESXi", "5.5");

build = int(match[1]);
fixed_build = 6480267;

if (build < fixed_build)
{
  report = '\n  ESXi version    : ' + ver +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fixed_build +
           '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware ESXi", ver - "ESXi " + " build " + build);
