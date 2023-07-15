#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77055);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id("CVE-2014-2972");
  script_bugtraq_id(68857);

  script_name(english:"Exim < 4.83 Math Comparison Functions Data Insertion");
  script_summary(english:"Checks the version of the SMTP banner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is potentially affected by a data insertion
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Exim running on the remote
host is prior to 4.83. It is, therefore, potentially affected by a
data insertion vulnerability. A flaw exists in the expansion of
arguments to math comparison functions which can cause values to be
expanded twice. This could permit a local attacker to insert arbitrary
data.");
  script_set_attribute(attribute:"see_also", value:"ftp://ftp.exim.org/pub/exim/exim4/");
  script_set_attribute(attribute:"see_also", value:"https://lists.exim.org/lurker/message/20140722.160524.be7e58a9.en.html");
  script_set_attribute(attribute:"see_also", value:"ftp://ftp.exim.org/pub/exim/ChangeLogs/ChangeLog-4.83");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Exim 4.83 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-2972");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:exim:exim");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smtpserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/smtp", 25);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);

banner = get_smtp_banner(port:port);
if (!banner) audit(AUDIT_NO_BANNER, port);
if ("Exim" >!< banner) audit(AUDIT_NOT_LISTEN, 'Exim', port);

matches = eregmatch(pattern:"220.*Exim ([0-9\.]+)", string:banner);
if (isnull(matches)) audit(AUDIT_SERVICE_VER_FAIL, 'Exim', port);

version = matches[1];
if (
     version =~ "^[0-3]\." ||
     version =~ "^4\.([0-7][0-9]|8[0-2])([^0-9]|$)"
   )
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Banner            : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.83';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'Exim', port, version);
