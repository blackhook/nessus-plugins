#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94165);
  script_version("1.13");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id(
    "CVE-2016-3492",
    "CVE-2016-5584",
    "CVE-2016-5616",
    "CVE-2016-5617",
    "CVE-2016-5626",
    "CVE-2016-5629",
    "CVE-2016-6662",
    "CVE-2016-7440",
    "CVE-2016-8283"
  );
  script_bugtraq_id(
    92912,
    93612,
    93614,
    93638,
    93650,
    93659,
    93668,
    93735,
    93737
  );
  script_xref(name:"EDB-ID", value:"40360");

  script_name(english:"MySQL 5.5.x < 5.5.53 Multiple Vulnerabilities (October 2016 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.5.x prior to
5.5.53. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in the Optimizer subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-3492)

  - An unspecified flaw exists in the Security: Encryption
    subcomponent that allows an authenticated, remote
    attacker to disclose sensitive information.
    (CVE-2016-5584)

  - An unspecified flaw exists in the MyISAM subcomponent
    that allows a local attacker to gain elevated
    privileges. (CVE-2016-5616)

  - An unspecified flaw exists in the Error Handling
    subcomponent that allows a local attacker to gain
    elevated privileges. (CVE-2016-5617)

  - An unspecified flaw exists in the GIS subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-5626)

  - An unspecified flaw exists in the Federated subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-5629)

  - A flaw exists in the check_log_path() function within
    file sql/sys_vars.cc due to inadequate restrictions on
    the ability to write to the my.cnf configuration file
    and allowing the loading of configuration files from
    path locations not used by current versions. An
    authenticated, remote attacker can exploit this issue
    by using specially crafted queries that utilize logging
    functionality to create new files or append custom
    content to existing files. This allows the attacker to
    gain root privileges by inserting a custom .cnf file
    with a 'malloc_lib=' directive pointing to specially
    crafted mysql_hookandroot_lib.so file and thereby cause
    MySQL to load a malicious library the next time it is
    started. (CVE-2016-6662)

  - A flaw exists in wolfSSL, specifically within the C
    software version of AES Encryption and Decryption, due
    to table lookups not properly considering cache-bank
    access times. A local attacker can exploit this, via a
    specially crafted application, to disclose AES keys.
    (CVE-2016-7440)

  - An unspecified flaw exists in the Types subcomponent
    that allows an authenticated, remote attacker to cause
    a denial of service condition.(CVE-2016-8283)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bac902d5");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-53.html");
  # http://legalhackers.com/advisories/MySQL-Exploit-Remote-Root-Code-Execution-Privesc-CVE-2016-6662.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fbd97f45");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.5.53 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6662");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.5.53', min:'5.5', severity:SECURITY_HOLE);
