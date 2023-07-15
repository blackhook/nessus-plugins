#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(63147);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/18");

  script_cve_id(
    "CVE-2012-0540",
    "CVE-2012-1689",
    "CVE-2012-1734",
    "CVE-2012-3150",
    "CVE-2012-3158",
    "CVE-2012-3160",
    "CVE-2012-3163",
    "CVE-2012-3166",
    "CVE-2012-3167",
    "CVE-2012-3173",
    "CVE-2012-3177",
    "CVE-2012-3180",
    "CVE-2012-3197",
    "CVE-2012-4414",
    "CVE-2012-5060",
    "CVE-2012-5611",
    "CVE-2013-1548"
  );
  script_bugtraq_id(56769);
  script_xref(name:"EDB-ID", value:"23075");

  script_name(english:"MariaDB 5.1 < 5.1.66 Buffer Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB 5.1 running on the remote host is prior to
5.1.66. It is, therefore, affected by a buffer overflow vulnerability.
A remote, authenticated attacker could exploit this to execute
arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2012/Dec/4");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-5166-release-notes/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 5.1.66 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-3163");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'5.1.66-MariaDB', min:'5.1', severity:SECURITY_HOLE);
