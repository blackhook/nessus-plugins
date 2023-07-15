#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(18034);
  script_version("1.33");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2004-1774",
    "CVE-2005-3202",
    "CVE-2005-3203",
    "CVE-2005-4832"
  );
  script_bugtraq_id(
    13139,
    13144,
    13145,
    13234,
    13235,
    13236,
    13238,
    13239,
    15031,
    15033
  );

  script_name(english:"Oracle Database 10g Multiple Remote Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server suffers from multiple flaws.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the installation of Oracle on the
remote host is reportedly subject to multiple vulnerabilities, some of
which don't require authentication.  They may allow an attacker to
craft SQL queries such that they would be able to retrieve any file on
the system and potentially retrieve and/or modify confidential data on
the target's Oracle server.");
  script_set_attribute(attribute:"solution", value:
"http://www.red-database-security.com/advisory/oracle_htmldb_css.html
http://www.red-database-security.com/advisory/oracle_htmldb_plaintext_password.html
http://www.oracle.com/technetwork/topics/security/cpuapr2005-132777.pdf");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-844");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2005-2022 Tenable Network Security, Inc.");

  script_dependencies("oracle_tnslsnr_version.nasl");
  script_require_ports("Services/oracle_tnslsnr");

  exit(0);
}

#broken
exit (0);

port = get_kb_item("Services/oracle_tnslsnr");
if (isnull(port)) exit(0);


version = get_kb_item(string("oracle_tnslsnr/", port, "/version"));
if (version) {
  if (ereg(pattern:".*Version (8\.(0\.|1\.([0-6]\.|7\.[0-4]))|9\.(0\.(0\.|1\.[0-5]|2\.[0-6]|3\.[0-1]|4\.[0-1])|2\.0\.[0-6])|10\.(0\.|1\.0\.[0-4])|11\.([0-4]\.|5\.[0-9][^0-9]))", string:version)) security_hole(port);
}
