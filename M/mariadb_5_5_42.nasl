#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121190);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/25");

  script_cve_id(
    "CVE-2015-0433",
    "CVE-2015-0441",
    "CVE-2015-2568",
    "CVE-2015-2573"
  );

  script_name(english:"MariaDB 5.5.0 < 5.5.42 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mariadb.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running of remote host is 5.5.0 prior to
5.5.42. It is, therefore, affected by multiple vulnerabilities");
  script_set_attribute(attribute:"see_also", value:"http://docs.tokutek.com/tokudb/tokudb-release-notes.html#tokudb-7-5-5");
  script_set_attribute(attribute:"see_also", value:"http://mariadb.org");
  script_set_attribute(attribute:"see_also", value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-2568");
  script_set_attribute(attribute:"see_also", value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-2573");
  script_set_attribute(attribute:"see_also", value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0433");
  script_set_attribute(attribute:"see_also", value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0441");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-5542-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 5.5.42 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2568");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
   script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant: 'MariaDB', min:'5.5.0-MariaDB', fixed:make_list('5.5.42-MariaDB'), severity:SECURITY_WARNING);