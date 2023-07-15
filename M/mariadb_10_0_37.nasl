#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121191);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/18");

  script_cve_id(
    "CVE-2016-9843",
    "CVE-2018-3143",
    "CVE-2018-3156",
    "CVE-2018-3174",
    "CVE-2018-3251",
    "CVE-2018-3282",
    "CVE-2019-2503"
  );
  script_bugtraq_id(
    95131,
    105600,
    105610,
    105612
  );

  script_name(english:"MariaDB 10.0.0 < 10.0.37 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running of remote host is 10.0.0 prior to
10.0.37. It is, therefore, affected by multiple vulnerabilities");
  script_set_attribute(attribute:"see_also", value:"https://lists.askmonty.org/cgi-bin/mailman/listinfo/announce");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.org/mariadb-10-0-37-now-available/");
  script_set_attribute(attribute:"see_also", value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3282");
  script_set_attribute(attribute:"see_also", value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-9843");
  script_set_attribute(attribute:"see_also", value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3174");
  script_set_attribute(attribute:"see_also", value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3143");
  script_set_attribute(attribute:"see_also", value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3156");
  script_set_attribute(attribute:"see_also", value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3251");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-17533");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-17532");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-17531");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-16465");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-12547");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-16865");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mdb-10037-rn");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.0.37 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9843");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/16");

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

mysql_check_version(variant: 'MariaDB', min:'10.0.0-MariaDB', fixed:make_list('10.0.37-MariaDB'), severity:SECURITY_HOLE);