#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72513);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-1643");
  script_bugtraq_id(65300);

  script_name(english:"Symantec Encryption Management Server < 3.3.2 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Encryption Management Server listening on the
remote host is earlier than version 3.3.2.  It is, therefore, affected
by an information disclosure vulnerability due to a flaw in the Web
Email Protection component.  A remote, authenticated attacker could
potentially exploit this vulnerability to view the contents of another
user's outbound emails.");
  # https://support.symantec.com/en_US/article.SYMSA1285.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f290741");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:encryption_management_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_encryption_server_detect.nbin");
  script_require_keys("LDAP/symantec_encryption_server/detected");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Symantec Encryption Management Server";

get_kb_item_or_exit("LDAP/symantec_encryption_server/detected");

port = get_service(svc:"ldap", default: 389, exit_on_fail:FALSE);

version = get_kb_item_or_exit("LDAP/symantec_encryption_server/" + port + "/version");
if (version =~ "^Unknown$") audit(AUDIT_UNKNOWN_APP_VER, app_name);
if (version !~ "^(\d+\.){2,}\d+$") audit(AUDIT_VER_NOT_GRANULAR, app_name, version);

fix = "3.3.2";
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(extra:report, port:port);
  }
  else security_warning(port:port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
