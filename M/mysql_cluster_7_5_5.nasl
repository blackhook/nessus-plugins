#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133181);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2018-2877");
  script_bugtraq_id(103838);
  script_xref(name:"IAVA", value:"2018-A-0121-S");

  script_name(english:"MySQL Cluster 7.2.x < 7.2.33 / 7.3.x < 7.3.21 / 7.4.x < 7.4.19 / 7.5.x < 7.5.10 Denial of Service Vulnerability");
  script_summary(english:"Checks the MySQL Cluster version");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL Cluster running on the remote host is 7.2.x prior to 7.2.33, 7.3.x prior to 7.3.21, 7.4.x prior to
7.4.19 or 7.5.x prior to 7.5.10. It is, therefore, affected by a denial of service vulnerability in the MySQL Cluster
component of Oracle MySQL (subcomponent: Cluster: ndbcluster/plugin). An authenticated, local attacker can exploit this,
to cause a hang or frequently repeatable crash of MySQL cluster.");
  # https://www.oracle.com/security-alerts/cpuapr2018.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbb08bd4");
  # https://www.oracle.com/security-alerts/cpuapr2018verbose.html#MSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aae7d01f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Cluster version 7.2.33 / 7.3.21 / 7.4.19 / 7.5.10 or later as referenced in the April 2018 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2877");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_cluster");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

mysql_check_version(variant:'Cluster', fixed:make_list('7.2.33', '7.3.21', '7.4.19', '7.5.10'), severity:SECURITY_NOTE);
