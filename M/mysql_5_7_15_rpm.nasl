#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93380);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/03");

  script_cve_id(
    "CVE-2016-3492",
    "CVE-2016-5507",
    "CVE-2016-5616",
    "CVE-2016-5617",
    "CVE-2016-5625",
    "CVE-2016-5626",
    "CVE-2016-5629",
    "CVE-2016-5632",
    "CVE-2016-6662",
    "CVE-2016-6663",
    "CVE-2016-8283",
    "CVE-2016-8286"
  );
  script_bugtraq_id(
    92911,
    92912,
    93612,
    93614,
    93617,
    93638,
    93650,
    93668,
    93678,
    93693,
    93737,
    93745
  );
  script_xref(name:"EDB-ID", value:"40360");

  script_name(english:"MySQL 5.7.x < 5.7.15 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.7.x prior to
5.7.15. It is, therefore, affected by multiple vulnerabilities :

  - Multiple unspecified flaws exist in the Optimizer
    subcomponent that allow an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-3492, CVE-2016-5632)

  - An unspecified flaw exists in the InnoDB subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-5507)

  - An unspecified flaw exists in the MyISAM subcomponent
    that allows a local attacker to gain elevated
    privileges. (CVE-2016-5616)

  - An unspecified flaw exists in the Error Handling
    subcomponent that allows a local attacker to gain
    elevated privileges. (CVE-2016-5617)

  - An unspecified flaw exists in the Packaging subcomponent
    that allows a local attacker to gain elevated
    privileges. (CVE-2016-5625)

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

  - An unspecified flaw exists that allows an authenticated,
    remote attacker to bypass restrictions and create the
    /var/lib/mysql/my.cnf file with custom contents without
    the FILE privilege requirement. (CVE-2016-6663)
    
  - An unspecified flaw exists in the Types subcomponent
    that allows an authenticated, remote attacker to cause
    a denial of service condition.(CVE-2016-8283)

  - An unspecified flaw exists in the Security: Privileges
    subcomponent that allows an authenticated, remote
    attacker to disclose sensitive information.
    (CVE-2016-8286)

  - A flaw exists that is related to the use of temporary
    files by REPAIR TABLE. An authenticated, remote attacker
    can exploit this to gain elevated privileges.

  - A flaw exists in InnoDB when handling an operation that
    dropped and created a full-text search table. An
    authenticated, remote attacker can exploit this to
    trigger an assertion, resulting in a denial of service
    condition.

  - A flaw exists in InnoDB when accessing full-text
    auxiliary tables while dropping the indexed table. An
    authenticated, remote attacker can exploit this to
    trigger an assertion, resulting in a denial of service
    condition.

  - A buffer overflow condition exists when handling long
    integer values in MEDIUMINT columns due to the improper
    validation of certain input. An authenticated, remote
    attacker can exploit this to cause a denial of service
    condition or the execution of arbitrary code.

  - An information disclosure vulnerability exists in the
    validate_password plugin due to passwords that have been
    rejected being written as plaintext to the error log. A
    local attacker can exploit this to more easily guess
    what passwords might have been chosen and accepted.

  - A flaw exists in InnoDB when handling an ALTER TABLE ...
    ENCRYPTION='Y', ALGORITHM=COPY operation that is applied
    to a table in the system tablespace. An authenticated,
    remote attacker can exploit this to trigger an
    assertion, resulting in a denial of service condition.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bac902d5");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-15.html");
  # http://legalhackers.com/advisories/MySQL-Exploit-Remote-Root-Code-Execution-Privesc-CVE-2016-6662.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fbd97f45");
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3235388.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?453a538d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.7.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6662");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/08");

  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");
  script_require_ports("Host/RedHat/release", "Host/AmazonLinux/release", "Host/SuSE/release", "Host/CentOS/release");

  exit(0);
}

include("mysql_version.inc");

fix_version = "5.7.15";
exists_version = "5.7";

mysql_check_rpms(mysql_packages:default_mysql_rpm_list_server_only, fix_ver:fix_version, exists_ver:exists_version, rhel_os_list:default_mysql_rhel_os_list, centos_os_list:default_mysql_centos_os_list, suse_os_list:default_mysql_suse_os_list, ala_os_list:default_mysql_ala_os_list, severity:SECURITY_HOLE);
