#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17805);
  script_version("1.6");
  script_cvs_date("Date: 2018/11/15 20:50:21");

  script_cve_id("CVE-2005-1636");
  script_bugtraq_id(13660);

  script_name(english:"MySQL < 4.1.12 / 5.0.4 Insecure Permissions");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary SQL commands may be run on the remote database server.");
  script_set_attribute(attribute:"description", value:
"The remote MySQL server is earlier than 4.1.12 / 5.0.4 and thus
reportedly creates a temporary file with insecure permissions and a
predictable name, which could allow a local user to run arbitrary SQL
commands.");
  script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=full-disclosure&m=111632686805498&w=2");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 4.1.12 / 5.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}


include("mysql_version.inc");

mysql_check_version(fixed:make_list('4.1.12', '5.0.4'), severity:SECURITY_WARNING);
