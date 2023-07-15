#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107258);
  script_version("1.6");
  script_cvs_date("Date: 2019/04/05 23:25:06");

  script_cve_id(
    "CVE-2016-1549",
    "CVE-2018-7170",
    "CVE-2018-7182",
    "CVE-2018-7183",
    "CVE-2018-7184",
    "CVE-2018-7185"
  );
  script_bugtraq_id(
    88200,
    103191,
    103192,
    103194,
    103339
  );

  script_name(english:"Network Time Protocol Daemon (ntpd) 4.x < 4.2.8p11 Multiple Vulnerabilities");
  script_summary(english:"Checks for a vulnerable NTP server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NTP server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the remote NTP server is 4.x prior to 4.2.8p11. It is,
therefore, affected by multiple vulnerabilities, which allow denial of
service attacks, information disclosure and possibly, remote code
execution.");
  # https://support.ntp.org/bin/view/Main/SecurityNotice#February_2018_ntp_4_2_8p11_NTP_S
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eda86736");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NTP version 4.2.8p11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7183");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/09");

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

match = pregmatch(string:version, pattern:"([0-9a-z.]+)");
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

# This vulnerability affects NTP 4.x < 4.2.8p11
# Check for vuln, else audit out.
if (
  (major == 4 && minor < 2) ||
  (major == 4 && minor == 2 && rev < 8) ||
  (major == 4 && minor == 2 && rev == 8 && patch < 11)
)
{
  fix = "4.2.8p11";
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
