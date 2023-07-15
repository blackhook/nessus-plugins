#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71116);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2012-5627");
  script_bugtraq_id(56837);

  script_name(english:"MySQL Server COM_CHANGE_USER Command Security Bypass");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote database server may be affected by a security bypass
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of MySQL may be affected by a security bypass
vulnerability because the salt used during password validation does not
change when switching users with the 'COM_CHANGE_USER' command.
Additionally, the connection is not reset when invalid credentials are
submitted.  Normally, when a connection is initiated and invalid
credentials are submitted, the connection is terminated, which slows
brute-force attempts substantially."
  );
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2012/Dec/58");
  script_set_attribute(attribute:"solution", value:"There is no solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5627");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/PCI_DSS");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("mysql_func.inc");

if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);

port = get_service(svc:'mysql', default:3306, exit_on_fail:TRUE);
mysql_init(port:port, exit_on_fail:TRUE);

if (is_mariadb()) audit(AUDIT_INST_VER_NOT_VULN, 'MariaDB');

# nb: There's currently no fix for 5.2.x, 5.3.x, or 5.5.x
# assume others are not affected
version = mysql_get_version();

if (version !~ "^5\.[235]\.")
{
  mysql_close();
  audit(AUDIT_INST_VER_NOT_VULN, "MySQL Server", version);
}

if (report_verbosity > 0)
{
  variant = mysql_get_variant();

  if (!isnull(variant) && !isnull(version))
  {
    report =
      '\n  Variant           : ' + variant +
      '\n  Installed version : ' + version +
      '\n';
    datadir = get_kb_item('mysql/' + port + '/datadir');
    if (!empty_or_null(datadir))
    {
      report += '  Data Dir          : ' + datadir + '\n';
    }
    databases = get_kb_item('mysql/' + port + '/databases');
    if (!empty_or_null(databases))
    { 
      report += '  Databases         :\n' + databases;
    }
  }
  else
  {
    report = 
      '\nNessus was able to determine a MySQL server is listening on' +
      '\nthe remote host but unable to determine its version and / or' +
      '\nvariant.' +
      '\n';
  }
  security_warning(port:port, extra:report);
}
else security_warning(port);
mysql_close();
