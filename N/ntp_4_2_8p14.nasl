#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135920);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/10");

  script_cve_id("CVE-2020-11868");
  script_xref(name:"IAVA", value:"2020-A-0167-S");

  script_name(english:"Network Time Protocol Daemon (ntpd) 4.x < 4.2.8p14 / 4.3.x < 4.3.100 DoS");
  script_summary(english:"Checks for a vulnerable NTP server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NTP server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the remote NTP server is 4.x prior to 4.2.8p14, or is
4.3.x prior to 4.3.100. It is, therefore, affected by a denial of
service vulnerability due to a flaw in handling unauthenticated
synchronization traffic. An authenticated attacker can exploit this
issue to cause denial of service.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3592");
  script_set_attribute(attribute:"see_also", value:"https://bugs.ntp.org/show_bug.cgi?id=3445");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NTP version 4.2.8p14, 4.3.100 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11868");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ntp_open.nasl");
  script_require_keys("NTP/Running", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

# Paranoia check
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Make sure NTP server is running
get_kb_item_or_exit('NTP/Running');

app_name = 'NTP Server';

port = get_kb_item('Services/udp/ntp');
if (empty_or_null(port)) port = 123;

version = get_kb_item_or_exit('Services/ntp/version');
if (version == 'unknown') audit(AUDIT_UNKNOWN_APP_VER, app_name);

match = pregmatch(string:version, pattern:"^([0-9]+\.[0-9]+\.[0-9p]+)");
if (empty_or_null(match)) audit(AUDIT_UNKNOWN_APP_VER, app_name);

ver = match[1];
verfields = split(ver, sep:'.', keep:FALSE);
major = int(verfields[0]);
minor = int(verfields[1]);
if ('p' >< verfields[2])
{
  revpatch = split(verfields[2], sep:'p', keep:FALSE);
  rev = int(revpatch[0]);
  patch = int(revpatch[1]);
}
else
{
  rev = verfields[2];
  patch = 0;
}

# This vulnerability affects NTP 4.x < 4.2.8p14
# Check for vuln, else audit out.
if (
  (major == 4 && minor < 2) ||
  (major == 4 && minor == 2 && rev < 8) ||
  (major == 4 && minor == 2 && rev == 8 && patch < 14)
)
{
  fix = '4.2.8p14';
}
else if (major == 4 && minor == 3 && rev < 100)
{
  fix = '4.3.100';
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

report =
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix +
  '\n';

security_report_v4(
  port  : port,
  proto : 'udp',
  extra : report,
  severity : SECURITY_WARNING
);
exit(0);
