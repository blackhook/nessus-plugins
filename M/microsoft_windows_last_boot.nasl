#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92366);
  script_version("1.7");
  script_cvs_date("Date: 2018/07/09 16:48:24");

  script_name(english:"Microsoft Windows Last Boot Time");
  script_summary(english:"Report last boot time.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to collect the remote host's last boot time in a human
readable format.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to collect and report the remote host's last boot time
as an ISO 8601 timestamp.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2016-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl","wmi_last_reboot.nbin");
  script_require_keys("Host/OS", "Host/last_reboot");

  exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("data_protection.inc");

os = get_kb_item_or_exit("Host/OS");
if("Windows" >!< os) audit(AUDIT_OS_NOT, "Windows");

# Disable if GDPR is set
data_protection::disable_plugin_if_set();

function wmi_datetime_to_timestamp(datetime)
{
  local_var result, wmi_min_off, hour_off, min_off;
  #ISO 8601
  #YYYY-MM-DDThh:mm:ssTZD (eg 1997-07-16T19:20:30+01:00)
  result = substr(datetime, 0, 3) + '-' + substr(datetime, 4, 5) + '-' + substr(datetime, 6, 7);
  result += 'T' + substr(datetime, 8, 9) + ':' + substr(datetime, 10, 11) + ':' + substr(datetime, 12, 13);
  wmi_min_off = int(substr(datetime, 22, 24));
  hour_off = wmi_min_off / 60;
  min_off = wmi_min_off % 60;

  result += datetime[21];
  if (hour_off < 10)
  {
    result += '0';
  }
  result += hour_off + ':';
  if (min_off < 10)
  {
    result += '0';
  }
  result += min_off;

  return result;
}

last_reboot = get_kb_item("Host/last_reboot");

if (isnull(last_reboot))
{
  exit(1, "Couldn't determine last boot.");
}

report = 'Last reboot : ' + wmi_datetime_to_timestamp(datetime:last_reboot) + ' (' + last_reboot + ')';
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
