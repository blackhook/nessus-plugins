#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119304);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id(
    "CVE-2018-11066",
    "CVE-2018-11067",
    "CVE-2018-11076",
    "CVE-2018-11077"
  );
  script_bugtraq_id(
    105968,
    105969,
    105971,
    105972
  );
  script_xref(name:"VMSA", value:"2018-0029");
  script_xref(name:"IAVA", value:"2018-A-0385");

  script_name(english:"VMware vSphere Data Protection 6.0.x < 6.0.9 / 6.1.x < 6.1.10 Multiple Vulnerabilities (VMSA-2018-0029)");
  script_summary(english:"Checks the version of VMware vSphere Data Protection.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization appliance installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vSphere Data Protection installed on the remote
host is 6.0.x < 6.0.9 and 6.1.x < 6.1.10. It is, therefore, affected
by the following vulnerabilities:

  - A remote command execution vulnerability. An unauthenticated,
    remote attacker can exploit this to bypass authentication and
    execute arbitrary commands. (CVE-2018-11066)

  - An open redirection vulnerability. An unauthenticated, remote
    attacker can exploit this to redirect application users to
    arbitrary, potentially malicious, web URLs. (CVE-2018-11067)

  - A command injection vulnerability exists in the 'getlogs'
    troubleshooting utility. An authenticated attacker with admin
    privileges can exploit this, to execute arbitrary commands
    with root privileges. (CVE-2018-11076)

  - An information disclosure vulnerability exists in Java
    management client package exposing the SSL/TLS private key.
    An unauthenticated, remote attacker can exploit this to
    conduct a MITM attack. (CVE-2018-11077)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0029.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vSphere Data Protection version 6.0.9 / 6.1.10 or
later..");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11066");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vsphere_data_protection");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/vSphere Data Protection/Version");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "vSphere Data Protection";

version = get_kb_item_or_exit("Host/vSphere Data Protection/Version");

if (version =~ "^[6]$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, version);

fix = '';

if (version =~ "^6\.0(\.)?")
{
 fix = "6.0.9";
}
else if (version =~ "^6\.1(\.)?")
{
 fix = "6.1.10";
}
else
  audit(AUDIT_NOT_INST, app_name + " 6.0.x / 6.1.x");

if (!empty(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{

  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
