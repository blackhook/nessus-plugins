#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103373);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-4925");
  script_bugtraq_id(100842);
  script_xref(name:"VMSA", value:"2017-0015");

  script_name(english:"VMware Fusion 8.x < 8.5.4 DoS Vulnerability (VMSA-2017-0015) (macOS)");
  script_summary(english:"Checks the VMware Fusion version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote macOS or Mac OS X
host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Fusion installed on the remote macOS or Mac OS X
host is 8.x prior to 8.5.4. It is, therefore, affected by a NULL pointer
dereference error related to handling RPC requests that allows an
attacker to crash a virtual machine.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/in/security/advisories/VMSA-2017-0015.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Fusion version 8.5.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4925");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "installed_sw/VMware Fusion", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_kb_item_or_exit("Host/local_checks_enabled");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

install = get_single_install(app_name:"VMware Fusion", exit_if_unknown_ver:TRUE);
version = install['version'];
path = install['path'];

fix = '';
if (version =~ "^8\.") fix = '8.5.4';

if (!empty(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report +=
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "VMware Fusion", version, path);
