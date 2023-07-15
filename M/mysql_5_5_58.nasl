#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104048);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id(
    "CVE-2017-10268",
    "CVE-2017-10378",
    "CVE-2017-10379",
    "CVE-2017-10384"
  );
  script_bugtraq_id(
    101375,
    101390,
    101406,
    101415
  );

  script_name(english:"MySQL 5.5.x < 5.5.58 Multiple Vulnerabilities (October 2017 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.5.x prior to
5.5.58. It is, therefore, affected by multiple vulnerabilities as
noted in the October 2017 Critical Patch Update advisory. Please
consult the CVRF details for the applicable CVEs for additional
information.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-58.html");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e07fa0e");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2307762.1");
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3937099.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e9f2a38");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.5.58 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10384");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.5.58', min:'5.5', severity:SECURITY_WARNING);
