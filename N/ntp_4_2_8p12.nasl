#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111968);
  script_version("1.4");
  script_cvs_date("Date: 2019/04/05 23:25:06");

  script_cve_id("CVE-2016-1549","CVE-2018-12327");

  script_name(english:"Network Time Protocol Daemon (ntpd) 4.x < 4.2.8p12 / 4.3.x < 4.3.94 Multiple Vulnerabilities");
  script_summary(english:"Checks for a vulnerable NTP server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NTP server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the remote NTP server is 4.x prior to 4.2.8p12, or is
4.3.x prior to 4.3.94. It is, therefore, affected by the following
vulnerabilities:

  - A race condition exists that is triggered during the
    handling of a saturation of ephemeral associations. An
    authenticated, remote attacker can exploit this to
    defeat NTP's clock selection algorithm and modify a
    user's clock. (CVE-2016-1549)

  - A buffer overflow vulnerability exists within the
    openhost() function of the ntpq anmd ntpdc. A local
    attacker, using an excessively large hostname, could
    cause a stack overflow and potentially allow for remote
    code execution or privilege escalation. (CVE-2018-12327)");
  # http://support.ntp.org/bin/view/Main/SecurityNotice#August_2018_ntp_4_2_8p12_NTP_Rel
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80cd6f97");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NTP version 4.2.8p12, 4.3.94 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12327");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ntp_open.nasl");
  script_require_keys("NTP/Running", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Make sure NTP server is running
get_kb_item_or_exit('NTP/Running');

app_name = "NTP Server";

port = get_kb_item("Services/udp/ntp");
if (empty_or_null(port)) port = 123;

version = get_kb_item_or_exit("Services/ntp/version");
if (version == 'unknown') audit(AUDIT_UNKNOWN_APP_VER, app_name);

match = pregmatch(string:version, pattern:"([0-9]+.[0-9]+.[0-9p]+)");
if (isnull(match) || empty_or_null(match[1])) audit(AUDIT_UNKNOWN_APP_VER, app_name);

# Paranoia check
if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = match[1];
verfields = split(ver, sep:".", keep:FALSE);
major = int(verfields[0]);
minor = int(verfields[1]);
if ('p' >< verfields[2])
{
  revpatch = split(verfields[2], sep:"p", keep:FALSE);
  rev = int(revpatch[0]);
  patch = int(revpatch[1]);
}
else
{
  rev = verfields[2];
  patch = 0;
}

# This vulnerability affects NTP 4.x < 4.2.8p12
# Check for vuln, else audit out.
if (
  (major == 4 && minor < 2) ||
  (major == 4 && minor == 2 && rev < 8) ||
  (major == 4 && minor == 2 && rev == 8 && patch < 12)
)
{
  fix = "4.2.8p12";
}
else if (major == 4 && minor == 3 && rev < 94)
{
  fix = "4.3.94";
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

report =
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix +
  '\n';

security_report_v4(
  port  : port,
  proto : "udp",
  extra : report,
  severity : SECURITY_HOLE
);
exit(0);
