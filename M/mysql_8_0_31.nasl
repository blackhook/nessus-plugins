#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166310);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2022-2097",
    "CVE-2022-21594",
    "CVE-2022-21599",
    "CVE-2022-21604",
    "CVE-2022-21608",
    "CVE-2022-21611",
    "CVE-2022-21617",
    "CVE-2022-21625",
    "CVE-2022-21632",
    "CVE-2022-21633",
    "CVE-2022-21637",
    "CVE-2022-21640",
    "CVE-2022-39400",
    "CVE-2022-39408",
    "CVE-2022-39410",
    "CVE-2023-21864",
    "CVE-2023-21865",
    "CVE-2023-21874",
    "CVE-2023-21912",
    "CVE-2023-21917"
  );
  script_xref(name:"IAVA", value:"2022-A-0432");
  script_xref(name:"IAVA", value:"2023-A-0043");
  script_xref(name:"IAVA", value:"2023-A-0212");

  script_name(english:"Oracle MySQL Server (Oct 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of MySQL Server installed on the remote host are affected by multiple vulnerabilities as referenced in the
October 2022 and January 2023 CPU advisories.

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions
    that are affected are 8.0.30 and prior. Easily exploitable vulnerability allows low privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS)
    of MySQL Server. (CVE-2022-39408)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that
    are affected are 8.0.30 and prior. Easily exploitable vulnerability allows low privileged attacker with network
    access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2022-39410)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Packaging (OpenSSL)). Supported
    versions that are affected are 5.7.39 and prior and 8.0.30 and prior. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks
    of this vulnerability can result in unauthorized read access to a subset of MySQL Server accessible data. (CVE-2022-2097)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2022.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2022 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2097");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include('mysql_version.inc');

mysql_check_version(fixed:'8.0.31', min:'8.0', severity:SECURITY_WARNING);
