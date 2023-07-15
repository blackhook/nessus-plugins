#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(164374);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2022-37451");
  script_xref(name:"IAVA", value:"2022-A-0338");

  script_name(english:"Exim < 4.96 DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is potentially affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Exim running on the remote host is prior to 4.96. It is, therefore,
potentially affected by an invalid free error which can be exploited by a remote, unauthenticated attacker.
Successful exploitation may result in a denial of service. This vulnerability requires PAM support and plaintext
authentication to be enabled.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.exim.org/show_bug.cgi?id=2813");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ivd38/exim_invalid_free");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Exim 4.96 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-37451");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:exim:exim");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smtpserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include('compat_shared.inc');
include('smtp_func.inc');

# The exploit requires a non-standard configuration
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var fixed_version = '4.96';
var port = get_service(svc:'smtp', default:25, exit_on_fail:TRUE);

var banner = get_smtp_banner(port:port);
if (!banner) audit(AUDIT_NO_BANNER, port);
if ('Exim' >!< banner) audit(AUDIT_NOT_LISTEN, 'Exim', port);

var matches = pregmatch(pattern:"220.*Exim ([0-9\._]+)", string:banner);
if (isnull(matches)) audit(AUDIT_SERVICE_VER_FAIL, 'Exim', port);

var version = matches[1];
# Underscore was added to the vesion
version = ereg_replace(string:version, pattern:'_', replace:'.');

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  var items = {
    'Banner': banner,
    'Installed version': version,
    'Fixed version': fixed_version
  };
  var ordering = ['Banner', 'Installed version', 'Fixed version'];
  var report = report_items_str(report_items:items, ordered_fields:ordering);

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'Exim', port, version);
