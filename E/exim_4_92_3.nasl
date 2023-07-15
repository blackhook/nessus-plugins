#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129470);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2019-16928");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"Exim 4.92.x < 4.92.3 Heap Buffer Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is potentially affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Exim running on the remote
host is 4.92.x prior to 4.92.3. It is, therefore, potentially affected
by a remote code execution vulnerability allowing unauthenticated,
remote attackers to execute arbitrary code via a heap buffer overflow
in string_vformat.");
  script_set_attribute(attribute:"see_also", value:"https://www.exim.org/static/doc/security/CVE-2019-16928.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Exim 4.92.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16928");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:exim:exim");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smtpserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/smtp", 25);

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('smtp_func.inc');

port = get_service(svc:'smtp', default:25, exit_on_fail:TRUE);

banner = get_smtp_banner(port:port);
if (!banner) audit(AUDIT_NO_BANNER, port);
if ('Exim' >!< banner) audit(AUDIT_NOT_LISTEN, 'Exim', port);

matches = pregmatch(pattern:"220.*Exim ([0-9\._]+)", string:banner);
if (isnull(matches)) audit(AUDIT_SERVICE_VER_FAIL, 'Exim', port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = matches[1];
# Underscore was added to the version
version = ereg_replace(string:version, pattern:"_", replace:".");

if (ver_compare(minver:'4.92', ver:version, fix:'4.92.3', strict:FALSE) < 0)
{
  report =
    '\n  Banner            : ' + banner +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 4.92.3';

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'Exim', port, version);
