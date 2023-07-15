#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100717);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-4914", "CVE-2017-4917");
  script_bugtraq_id(98936, 98939);
  script_xref(name:"VMSA", value:"2017-0010");

  script_name(english:"VMware vSphere Data Protection 5.5.x / 5.8.x / 6.0.x < 6.0.5 / 6.1.x < 6.1.4 Multiple Vulnerabilities (VMSA-2017-0010");
  script_summary(english:"Checks the version of VMware vSphere Data Protection.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization appliance installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vSphere Data Protection installed on the remote
host is 5.5.x, 5.8.x, or 6.0.x prior to 6.0.5, or it is 6.1.x prior to
6.1.14. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists when handling Java
    deserialization that allows an unauthenticated, remote
    attacker to execute arbitrary commands on the appliance.
    (CVE-2017-4914)

  - An information disclosure vulnerability exists due to
    using a weak encryption algorithm that allows a local
    attacker to disclose credentials. (CVE-2017-4917)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2017-0010.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vSphere Data Protection version 6.0.5 / 6.1.14 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4914");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vsphere_data_protection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (version =~ "^[56]$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, version);

fix = NULL;

if (version =~ "^5\.[58]|^6\.0(\.)?")
{
 fix = "6.0.5";
}
else if (version =~ "^6\.1(\.)?")
{
 fix = "6.1.4";
}
else
  audit(AUDIT_NOT_INST, app_name + " 5.5.x / 5.8.x / 6.0.x / 6.1.x");

if (!empty(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{

  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
