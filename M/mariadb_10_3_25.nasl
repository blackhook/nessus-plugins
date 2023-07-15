##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141198);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/11");

  script_cve_id("CVE-2020-15180");

  script_name(english:"MariaDB 10.3.0 < 10.3.25 A Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 10.3.25. It is, therefore, affected by a vulnerability
as referenced in the mdb-10325-rn advisory. Note that Nessus has not tested for this issue but has instead relied only
on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mdb-10325-rn");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.3.25 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15180");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include('mysql_version.inc');

mysql_check_version(variant: 'MariaDB', min:'10.3.0-MariaDB', fixed:make_list('10.3.25-MariaDB'), severity:SECURITY_WARNING);