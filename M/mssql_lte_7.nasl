#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11870);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2000-0199");
  script_bugtraq_id(1055);

  script_name(english:"Microsoft SQL Server < 7 Local Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote SQL Server is affected by a local privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"Based on its version number, the remote host may be vulnerable to a
local exploit wherein an authenticated user can obtain and crack SQL
usernames and passwords from the registry. 

An attacker may use this flaw to elevate their privileges on the local
database. 

*** This alert might be a false positive, as Nessus did not actually
*** check for this flaw but relied solely on the presence of Microsoft
*** SQL 7 to issue this alert.");
  # http://web.archive.org/web/20131113182136/http://www.iss.net:80/threats/advise45.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ed99acb");
  script_set_attribute(attribute:"solution", value:
"Ensure that the configuration has enabled Always prompting for login
name and password.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2000-0199");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2003-2022 Tenable Network Security, Inc.");

  script_dependencies("mssql_version.nasl");
  script_require_keys("mssql/installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

sql_ver_list = get_kb_list("mssql/installs/*/SQLVersion");
if (isnull(sql_ver_list)) audit(AUDIT_NOT_INST, "Microsoft SQL Server");

port = kb_smb_transport();

foreach item (keys(sql_ver_list))
{
  version = get_kb_item(item);
  if (!isnull(version) && egrep(pattern:"^[67]\..*" , string:version))
  {
    base_key = ereg_replace(pattern:"^(.*/).*$", string: item, replace: "\1");
    verbose_version = get_kb_item(base_key + "SQLVerboseVersion");
    if(!isnull(verbose_version)) version += ' (' + verbose_version + ')';
    edition_type = get_kb_item(base_key + "edition_type");
    if(!isnull(edition_type)) version += ' ' + edition_type;
    else
    {
      edition = get_kb_item(base_key + "edition");
      if(!isnull(edition)) version += " " + edition;
    }

    instance = get_kb_item(base_key + "NamedInstance");

    report =
      '\n  Installed version : ' + version +
      '\n  Instance name     : ' + instance +
      '\n';

    security_report_v4(extra:report, port:port, severity:SECURITY_HOLE);

    exit(0);
  }
}

audit(AUDIT_INST_VER_NOT_VULN, "Microsoft SQL Server");
