#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105586);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2017-15548", "CVE-2017-15549", "CVE-2017-15550");
  script_bugtraq_id(102352, 102358, 102363);

  script_name(english:"VMware vSphere Data Protection 5.x / 6.0.x < 6.0.7 / 6.1.x < 6.1.6 Multiple Vulnerabilities (VMSA-2018-0001");
  script_summary(english:"Checks the version of VMware vSphere Data Protection.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization appliance installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vSphere Data Protection installed on the remote
host is 5.x or 6.0.x prior to 6.0.7, or it is 6.1.x prior to
6.1.6. It is, therefore, affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0001.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vSphere Data Protection version 6.0.7 / 6.1.6 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15548");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vsphere_data_protection");
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

if (version =~ "^[56]$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, version);

fix = NULL;

if (version =~ "^5\.[0-9]|^6\.0(\.)?")
{
 fix = "6.0.7";
}
else if (version =~ "^6\.1(\.)?")
{
 fix = "6.1.6";
}
else
  audit(AUDIT_NOT_INST, app_name + " 5.x / 6.0.x / 6.1.x");

if (!empty(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{

  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
