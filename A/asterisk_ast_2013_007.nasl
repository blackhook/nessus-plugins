#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71538);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-7100");
  script_bugtraq_id(64364, 64367);

  script_name(english:"Asterisk Multiple Vulnerabilities (AST-2013-006 / AST-2013-007)");

  script_set_attribute(attribute:"synopsis", value:
"A telephony application running on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to the version in its SIP banner, the version of Asterisk
running on the remote host is potentially affected by the following
vulnerabilities :

  - A denial of service vulnerability exists in the
    'unpacksms16()' function of the 'app_sms.c' source file.
    When a 16-bit SMS message with an unusual message length
    value is received, an infinite loop will be created,
    causing a denial of service.

  - A privilege escalation vulnerability exists because of
    the way dialplan functions are handled during variable
    substitution.  Privileged dialplan functions, such as
    the SHELL() and FILE() functions, can be used by
    external control protocols, such as the Asterisk Manager
    Interface and Asterisk Gateway Interface.  A malicious,
    authenticated user could use these functions to modify
    arbitrary files or execute arbitrary commands.");
  script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/AST-2013-006.html");
  script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/AST-2013-007.html");
  script_set_attribute(attribute:"see_also", value:"https://issues.asterisk.org/jira/browse/ASTERISK-22590");
  script_set_attribute(attribute:"see_also", value:"https://issues.asterisk.org/jira/browse/ASTERISK-22905");
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.8.24.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5269580c");
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-10.4.2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?989ff925");
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-11.6.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f8ef69c");
  # http://downloads.asterisk.org/pub/telephony/certified-asterisk/releases/ChangeLog-1.8.15-cert4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1df629a");
  # http://downloads.asterisk.org/pub/telephony/certified-asterisk/releases/ChangeLog-11.2-cert3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60d42add");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Asterisk 1.8.24.1 / 10.12.4 / 11.6.1 / Certified Asterisk
1.8.15-cert4 / 11.2-cert3, or apply the appropriate patches or
workaround contained in the Asterisk advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-7100");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:digium:asterisk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("asterisk_detection.nasl");
  script_require_keys("asterisk/sip_detected", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("asterisk/sip_detected");

# see if we were able to get version info from the Asterisk SIP services
asterisk_kbs = get_kb_list("sip/asterisk/*/version");
if (isnull(asterisk_kbs)) exit(1, "Could not obtain any version information from the Asterisk SIP instance(s).");

# Prevent potential false positives.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

is_vuln = FALSE;
not_vuln_installs = make_list();
errors = make_list();

foreach kb_name (keys(asterisk_kbs))
{
  vulnerable = 0;

  matches = eregmatch(pattern:"/(udp|tcp)/([0-9]+)/version", string:kb_name);
  if (isnull(matches))
  {
    errors = make_list(errors, "Unexpected error parsing port number from '"+kb_name+"'.");
    continue;
  }

  proto = matches[1];
  port  = matches[2];
  version = asterisk_kbs[kb_name];

  if (version == 'unknown')
  {
    errors = make_list(errors, "Unable to obtain version of install on " + proto + "/" + port + ".");
    continue;
  }

  banner = get_kb_item("sip/asterisk/" + proto + "/" + port + "/source");
  if (!banner)
  {
    # We have version but banner is missing; log error
    # and use in version-check though.
    errors = make_list(errors, "KB item 'sip/asterisk/" + proto + "/" + port + "/source' is missing.");
    banner = 'unknown';
  }

  # Open Source 10x < 10.12.4
  if (version =~ "^10([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "10.12.4";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Open Source 11x < 11.6.1
  if (version =~ "^11([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "11.6.1";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Open Source 1.8.x < 1.8.24.1
  if (version =~ "^1\.8([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "1.8.24.1";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Asterisk Certified 1.8.15-cert4
  if (version =~ "^1\.8\.15([^0-9])" && "cert" >< tolower(version))
  {
    fixed = "1.8.15-cert4";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Asterisk Certified 11.2.x < 11.2-cert3
  if (version =~ "^11\.2([^0-9])" && "cert" >< tolower(version))
  {
    fixed = "11.2-cert3";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }
  if (vulnerable < 0)
  {
    is_vuln = TRUE;
    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + banner +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed + '\n';
      security_warning(port:port, proto:proto, extra:report);
    }
    else security_warning(port:port, proto:proto);
  }
  else not_vuln_installs = make_list(not_vuln_installs, version + " on port " + proto + "/" + port);
}

if (max_index(errors))
{
  if (max_index(errors) == 1) errmsg = errors[0];
  else errmsg = 'Errors were encountered verifying installs : \n  ' + join(errors, sep:'\n  ');

  exit(1, errmsg);
}
else
{
  installs = max_index(not_vuln_installs);
  if (installs == 0)
  {
    if (is_vuln)
      exit(0);
    else
      audit(AUDIT_NOT_INST, "Asterisk");
  }
  else if (installs == 1) audit(AUDIT_INST_VER_NOT_VULN, "Asterisk " + not_vuln_installs[0]);
  else exit(0, "The Asterisk installs (" + join(not_vuln_installs, sep:", ") + ") are not affected.");
}
