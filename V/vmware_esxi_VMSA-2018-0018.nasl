#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134878);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/02");

  script_cve_id("CVE-2018-6972");
  script_bugtraq_id(104884);
  script_xref(name:"VMSA", value:"2018-0018");

  script_name(english:"VMware ESXi 5.5 / 6.0 / 6.5 / 6.7 DoS (VMSA-2018-0018) (remote check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is missing a security patch and is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is version 5.5, 6.0, 6.5, or 6.7 and is missing a security patch. It is, therefore,
vulnerable to a denial of service vulnerability. The vulnerability exists in the RPC handler due to a NULL pointer
dereference issue. An authenticated, remote attacker can exploit this issue to cause VMs to stop responding.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0018.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6972");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release", "Host/VMware/vsphere");

  exit(0);
}

fixes = make_array(
  '5.5', '8934887',
  '6.0', '8934903',
  '6.5', '8935087',
  '6.7', '8941472'
);

rel = get_kb_item_or_exit("Host/VMware/release");
if ("ESXi" >!< rel) audit(AUDIT_OS_NOT, "ESXi");

ver = get_kb_item_or_exit("Host/VMware/version");
port = get_kb_item_or_exit("Host/VMware/vsphere");

match = pregmatch(pattern:"^ESXi? ([0-9]+\.[0-9]+).*$", string:ver);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, "VMware ESXi", "5.5 / 6.0 / 6.5 / 6.7");
ver = match[1];

if (ver != '5.5' && ver != '6.0' && ver != '6.5' && ver != '6.7')
  audit(AUDIT_OS_NOT, "ESXi 5.5 / 6.0 / 6.5 / 6.7");

fixed_build = fixes[ver];

if (empty_or_null(fixed_build)) audit(AUDIT_VER_FORMAT, ver);

match = pregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, "VMware ESXi", "5.5 / 6.0 / 6.5 / 6.7");

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
