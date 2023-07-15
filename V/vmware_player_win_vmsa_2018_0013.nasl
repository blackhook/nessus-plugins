#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110098);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-6963");
  script_bugtraq_id(104237);
  script_xref(name:"VMSA", value:"2018-0013");

  script_name(english:"VMware Player 14.x < 14.1.2 Multiple DoS (VMSA-2018-0013)");
  script_summary(english:"Checks the VMware Player version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Player installed on the remote Windows host
is 14.x prior to 14.1.2. It is, therefore, missing a security
update that fixes multiple RPC related flaws that allow denial of
service attacks.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/us/security/advisories/VMSA-2018-0013.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Player version 14.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6963");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_player_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Player");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

install = get_single_install(app_name:"VMware Player", exit_if_unknown_ver:TRUE);
version = install['version'];
path = install['path'];

fix = '';
if (version =~ "^14\.") fix = '14.1.2';
else audit(AUDIT_INST_PATH_NOT_VULN, "VMware Player", version, path);

if (!empty(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report +=
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "VMware Player", version, path);
