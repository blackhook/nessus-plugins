#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121422);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/18");

  script_cve_id(
    "CVE-2018-2562",
    "CVE-2018-2612",
    "CVE-2018-2622",
    "CVE-2018-2640",
    "CVE-2018-2665",
    "CVE-2018-2668"
  );
  script_bugtraq_id(
    102678,
    102681,
    102682,
    102706,
    102709,
    102713,
    105610
  );

  script_name(english:"MariaDB 10.1 < 10.1.31 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running of remote host is 10.1 prior to
10.1.31. It is, therefore, affected by multiple vulnerabilities");
  script_set_attribute(attribute:"see_also", value:"https://lists.askmonty.org/cgi-bin/mailman/listinfo/announce");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mdb-10131-rn");
  script_set_attribute(attribute:"see_also", value:"http://cve.mitre.org/cgi/bin/cvename.cgi?name=CVE-2018-2562");
  script_set_attribute(attribute:"see_also", value:"http://cve.mitre.org/cgi/bin/cvename.cgi?name=CVE-2018-2612");
  script_set_attribute(attribute:"see_also", value:"http://cve.mitre.org/cgi/bin/cvename.cgi?name=CVE-2018-2622");
  script_set_attribute(attribute:"see_also", value:"http://cve.mitre.org/cgi/bin/cvename.cgi?name=CVE-2018-2640");
  script_set_attribute(attribute:"see_also", value:"http://cve.mitre.org/cgi/bin/cvename.cgi?name=CVE-2018-2665");
  script_set_attribute(attribute:"see_also", value:"http://cve.mitre.org/cgi/bin/cvename.cgi?name=CVE-2018-2668");
  script_set_attribute(attribute:"see_also", value:"http://cve.mitre.org/cgi/bin/cvename.cgi?name=CVE-2018-3133");
  # https://github.com/MariaDB/server/commit/ab1e6fefd869242d962cb91a006f37bb9ad534a7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e7fe54c");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-13205");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-13499");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-14174");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-14776");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-14799");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-14874");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-7049");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.1.31 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2612");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-2562");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant: 'MariaDB', min:'10.1.0-MariaDB', fixed:make_list('10.1.31-MariaDB'), severity:SECURITY_HOLE);