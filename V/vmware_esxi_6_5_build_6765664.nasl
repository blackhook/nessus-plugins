#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105614);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/02");

  script_cve_id("CVE-2017-4933");
  script_bugtraq_id(102240);
  script_xref(name:"VMSA", value:"2017-0021");

  script_name(english:"ESXi 6.5 < Build 6765664 Heap Buffer Overflow (VMSA-2017-0021) (remote check)");
  script_summary(english:"Checks the ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 6.5 host is affected by a remote
heap buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the remote VMware ESXi 6.5 host is prior to build
6765664. It is, therefore, affected by a heap buffer overflow vulnerability that
can be triggered by a specially crafted set of VNC packets.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2017-0021.html");
  script_set_attribute(attribute:"see_also", value:"https://www.talosintelligence.com/vulnerability_reports/TALOS-2017-0368");
  script_set_attribute(attribute:"solution", value:
"Apply patch ESXi650-201710401-BG according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4933");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:vmware:esxi:6.5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release", "Host/VMware/vsphere");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/VMware/version");
rel = get_kb_item_or_exit("Host/VMware/release");
port = get_kb_item_or_exit("Host/VMware/vsphere");

if ("ESXi" >!< rel) audit(AUDIT_OS_NOT, "ESXi");
if ("VMware ESXi 6.5" >!< rel) audit(AUDIT_OS_NOT, "ESXi 6.5");

match = pregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, "VMware ESXi", "6.5");

build = int(match[1]);
fixed_build = 6765664;

if (build < fixed_build)
{
  report = '\n  ESXi version    : ' + ver +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fixed_build +
           '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware ESXi", ver - "ESXi " + " build " + build);
