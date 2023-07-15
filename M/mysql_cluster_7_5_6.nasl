#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99520);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-3304");
  script_bugtraq_id(97815);

  script_name(english:"MySQL Cluster 7.5.x < 7.5.6 DD Subcomponent Arbitrary Data Manipulation (April 2017 CPU)");
  script_summary(english:"Checks the MySQL Cluster version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by an arbitrary data
manipulation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL Cluster running on the remote host is 7.5.x prior
to 7.5.6. It is, therefore, affected by an arbitrary data
manipulation vulnerability in the DD subcomponent due to an
unspecified flaw. An authenticated, remote attacker can exploit this
to update, insert, or delete arbitrary data or cause a partial denial
of service condition.");
  # https://dev.mysql.com/doc/relnotes/mysql-cluster/7.5/en/mysql-cluster-news-7-5-6.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?214cccc1");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d679be85");
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3681811.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb4db3c7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Cluster version 7.5.6 or later as referenced in the
April 2017 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3304");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/20");

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

mysql_check_version(variant:'Cluster', fixed:'7.5.6', min:'7.5', severity:SECURITY_WARNING);
