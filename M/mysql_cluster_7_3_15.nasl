#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96726);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2016-5541", "CVE-2017-3322", "CVE-2017-3323");
  script_bugtraq_id(95574, 95575, 95592);

  script_name(english:"MySQL Cluster 7.3.x < 7.3.15 Multiple Vulnerabilities (January 2017 CPU)");
  script_summary(english:"Checks the MySQL Cluster version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL Cluster running on the remote host is 7.3.x prior
to 7.3.15. It is, therefore, affected by multiple vulnerabilities :

  - An overflow condition exists in the NDBAPI subcomponent
    that allows an unauthenticated, remote attacker to
    update, insert, or delete arbitrary data.
    (CVE-2016-5541)

  - An overflow condition exists in the NDBAPI subcomponent
    that allows an unauthenticated, remote attacker to cause
    a denial of service condition. (CVE-2017-3322)

  - An unspecified flaw exists in the General subcomponent
    that allows an unauthenticated, remote attacker to cause
    a denial of service condition. (CVE-2017-3323)");
  # https://dev.mysql.com/doc/relnotes/mysql-cluster/7.3/en/mysql-cluster-news-7-3-15.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27ecedfe");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1c38e52");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Cluster version 7.3.15 or later as referenced in the
January 2017 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5541");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_cluster");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'Cluster', fixed:'7.3.15', min:'7.3', severity:SECURITY_WARNING);
