#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(105077);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/18");

  script_cve_id("CVE-2017-10268", "CVE-2017-10378", "CVE-2017-15365");
  script_bugtraq_id(
    95527,
    96162,
    97725,
    97742,
    97776,
    97831,
    99736,
    99767,
    99810,
    101375,
    101390,
    101406,
    101415
  );

  script_name(english:"MariaDB 10.2.x < 10.2.10  Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 10.2.x prior to
10.2.10. It is, therefore, affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-10210-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/security/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.2.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15365");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB',min:'10.2.0-MariaDB', fixed:make_list('10.2.10-MariaDB'), severity:SECURITY_WARNING);
