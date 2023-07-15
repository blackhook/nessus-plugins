#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121311);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id("CVE-2015-5300");

  script_name(english:"Network Time Protocol Daemon (ntpd) 3.x / 4.x < 4.2.8p5 Denial Of Service Vulnerability");
  script_summary(english:"Checks for a vulnerable NTP server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NTP server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the remote NTP server is 3.x or 4.x prior to 4.2.8p5.
It is, therefore, affected by the following vulnerability :

  - he panic_gate check in NTP before 4.2.8p5 is only re-enabled 
    after the first change to the system clock that was greater than
    128 milliseconds by default, which allows remote attackers to set
    NTP to an arbitrary time when started with the -g option, or to
    alter the time by up to 900 seconds otherwise by responding to an
    unspecified number of requests from trusted sources, and 
    leveraging a resulting denial of service (abort and restart).
    (CVE-2015-7691)");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug2956");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/SecurityNotice");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NTP version 4.2.8p5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5300");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!port) port = 123;

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

# This vulnerability affects NTP 3.x / 4.x < 4.2.8p4
if (
  (major < 4 && major >= 3) ||
  (major == 4 && minor < 2) ||
  (major == 4 && minor == 2 && rev < 8) ||
  (major == 4 && minor == 2 && rev == 8 && patch < 5)
)
{
  fix = "4.2.8p5";
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
  severity : SECURITY_WARNING
);
exit(0);
