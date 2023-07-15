#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(79826);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/18");

  script_cve_id(
    "CVE-2014-2430",
    "CVE-2014-2431",
    "CVE-2014-2436",
    "CVE-2014-2440",
    "CVE-2019-2481"
  );
  script_bugtraq_id(
    66850,
    66858,
    66890,
    66896
  );

  script_name(english:"MariaDB 5.5 < 5.5.37 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB 5.5 running on the remote host is a version
prior to 5.5.37. It is, therefore, potentially affected by
vulnerabilities due to errors related to the following components :

  - Client
  - Options
  - Performance Schema
  - RBR");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/library/mariadb-5537-changelog/");
  # https://mariadb.com/kb/en/library/mariadb-5537-release-notes/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e66ff27");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB 5.5.37 or later or apply the vendor patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-2436");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-2481");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'5.5.37-MariaDB', min:'5.5', severity:SECURITY_WARNING);
