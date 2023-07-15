#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130026);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/21");

  script_cve_id(
    "CVE-2019-2910",
    "CVE-2019-2911",
    "CVE-2019-2914",
    "CVE-2019-2922",
    "CVE-2019-2923",
    "CVE-2019-2924",
    "CVE-2019-2938",
    "CVE-2019-2946",
    "CVE-2019-2960",
    "CVE-2019-2974",
    "CVE-2019-2993",
    "CVE-2019-5443",
    "CVE-2020-2752"
  );
  script_bugtraq_id(108881);
  script_xref(name:"IAVA", value:"2020-A-0143-S");

  script_name(english:"MySQL 5.7.x < 5.7.28 Multiple Vulnerabilities (Oct 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.7.x prior to 5.7.28. It is, therefore, affected by multiple
vulnerabilities, including three of the top vulnerabilities below, as noted in the October 2019 Critical Patch Update
advisory:

  - Vulnerabilities in the MySQL Server product of Oracle MySQL (component: Server: Optimizer and PS). Easily
  exploitable vulnerabilities which allow low privileged attackers with network access via multiple protocols to
  compromise MySQL Server. Successful exploitation of these vulnerabilities can result in unauthorized ability to cause
  a hang or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2019-2946, CVE-2019-2974)

  - A non-privileged user or program can put code and a config file in a known non-privileged path (under
  C:/usr/local/) that will make curl <= 7.65.1 automatically run the code (as an openssl 'engine') on invocation.
  If that curl is invoked by a privileged user it can do anything it wants. (CVE-2019-5443)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-28.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?41ee55d1");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b370bc74");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.7.28 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2924");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-5443");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include('mysql_version.inc');
mysql_check_version(fixed:'5.7.28', min:'5.7.0', severity:SECURITY_WARNING);
