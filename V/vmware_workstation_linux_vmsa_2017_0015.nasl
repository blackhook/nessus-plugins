#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103379);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/21");

  script_cve_id("CVE-2017-4924", "CVE-2017-4925");
  script_bugtraq_id(100842, 100843);
  script_xref(name:"VMSA", value:"2017-0015");

  script_name(english:"VMware Workstation 12.x < 12.5.7 Multiple Vulnerabilities (VMSA-2017-0015) (Linux)");
  script_summary(english:"Checks the VMware Workstation version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Linux host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote Linux host
is 12.x prior to 12.5.7. It is, therefore, affected by the following
vulnerabilities:

  - A remote code execution vulnerability exists in VMware
    workstation within the SVGA device. An attacker with
    user access can exploit this to execute arbitrary
    code. (CVE-2017-4924)

  - A denial of service vulnerability exists in VMware
    workstation due to a NULL pointer deference when
    handling guest RPC requests. An attacker with guest
    access can exploit this to crash their VMs.
    NOTE: This vulnerability only affects VMware
    Workstation 12.5.2 and below. (CVE-2017-4925)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2017-0015.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation version 12.5.7 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4924");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_linux_installed.nbin");
  script_require_keys("Host/VMware Workstation/Version", "Settings/ParanoidReport");
  script_exclude_keys("SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (get_kb_item("SMB/Registry/Enumerated")) audit(AUDIT_OS_NOT, "Linux", "Windows");

version = get_kb_item_or_exit("Host/VMware Workstation/Version");

fix = '';
if (version =~ "^12\.") fix = '12.5.7';

if (!empty(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report +=
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware Workstation", version);
