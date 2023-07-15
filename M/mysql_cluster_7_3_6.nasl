#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101811);
  script_version("1.8");
  script_cvs_date("Date: 2018/07/17 12:00:06");

  script_cve_id("CVE-2014-1912");
  script_bugtraq_id(65379);
  script_xref(name:"EDB-ID", value:"31875");

  script_name(english:"MySQL Cluster 7.3.x < 7.3.6 CLSTCONF RCE (July 2017 CPU)");
  script_summary(english:"Checks the MySQL Cluster version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL Cluster running on the remote host is 7.3.x prior
to 7.3.6. It is, therefore, affected by an overflow condition in the
CLSTCONF component, specifically in the Python sock_recvfrom_into()
function within file Modules/socketmodule.c, due to improper
validation of user-supplied input when checking boundaries. An
unauthenticated, remote attacker can exploit this, via a specially
crafted string, to cause a denial of service condition or the
execution of arbitrary code.");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50229a1a");
  # https://dev.mysql.com/doc/relnotes/mysql-cluster/7.3/en/mysql-cluster-news-7-3-6.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32fa85d0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Cluster version 7.3.6 or later as referenced in the
July 2017 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_cluster");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'Cluster', fixed:'7.3.6', min:'7.3', severity:SECURITY_HOLE);
