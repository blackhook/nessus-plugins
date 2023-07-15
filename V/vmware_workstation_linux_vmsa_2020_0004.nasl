#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134626);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/12");

  script_cve_id("CVE-2019-5543", "CVE-2020-3947", "CVE-2020-3948");
  script_xref(name:"VMSA", value:"2020-0004");

  script_name(english:"VMware Workstation 15.x < 15.5.2 Multiple Vulnerabilities (VMSA-2020-0004) (Linux)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Linux host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote Linux host
is 15.x prior to 15.5.2. It is, therefore, affected by multiple
vulnernabilities.  Note that Nessus has not tested for these issues
but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2020-0004.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation version 15.5.2, or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3947");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_linux_installed.nbin");
  script_require_keys("Host/VMware Workstation/Version", "Settings/ParanoidReport");
  script_exclude_keys("SMB/Registry/Enumerated");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (get_kb_item("SMB/Registry/Enumerated")) audit(AUDIT_OS_NOT, "Linux", "Windows");

version = get_kb_item_or_exit("Host/VMware Workstation/Version");

fix = '';
if (version =~ "^15\.") fix = '15.5.2';

if (!empty(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report +=
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware Workstation", version);
