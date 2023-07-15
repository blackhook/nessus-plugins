#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103857);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2017-13077",
    "CVE-2017-13078",
    "CVE-2017-13079",
    "CVE-2017-13080",
    "CVE-2017-13081",
    "CVE-2017-13082",
    "CVE-2017-13083",
    "CVE-2017-13084",
    "CVE-2017-13085",
    "CVE-2017-13086",
    "CVE-2017-13087"
  );
  script_bugtraq_id(101274);
  script_xref(name:"IAVA", value:"2017-A-0310");

  script_name(english:"MikroTik RouterOS < 6.39.3 / 6.40.4 / 6.41rc (KRACK)");

  script_set_attribute(attribute:"synopsis", value:
"The remote networking device is affected by a heap corruption
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote networking device
is running a version of MikroTik 6.9.X prior to 6.39.3, 6.40.x <
6.40.4, or 6.41rc. It, therefore, vulnerable to multiple
vulnerabilities discovered in the WPA2 handshake protocol.");
  # https://forum.mikrotik.com/viewtopic.php?f=21&t=126695
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db1a2125");
  script_set_attribute(attribute:"see_also", value:"https://forum.mikrotik.com/viewtopic.php?f=21&t=126694");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MikroTik RouterOS 6.39.3 / 6.40.4 / 6.41rc or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-13083");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mikrotik:routeros");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mikrotik_detect.nasl", "ssh_detect.nasl");
  script_require_keys("MikroTik/RouterOS/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("MikroTik/RouterOS/Version");
rep_extra = '';

port = 0;
if (report_paranoia < 2)
{
  port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);
  banner = get_kb_item_or_exit("SSH/banner/"+port);
  if ("ROSSSH" >!< banner) audit(AUDIT_NOT_LISTEN, 'Mikrotik RouterOS sshd', port);
}

if (version =~ "^[0-5]\.")
{
  fix = "6.39.3";
  rep_extra = " or 6.40.4 or 6.41rc";
}
else if (version =~ "^6\.39")
{
  fix = "6.39.3";
  rep_extra = " or 6.41rc";
}
else if (version =~ "^6\.40")
{
  fix = "6.40.4";
  rep_extra = " or 6.41rc";
}
else
  audit(AUDIT_HOST_NOT, "affected");

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  report =
    '\n  Installed version : '+version+
    '\n  Fixed version     : '+ fix + rep_extra +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_HOST_NOT, "affected");
