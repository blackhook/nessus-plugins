##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163333);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2018-25032",
    "CVE-2022-1292",
    "CVE-2022-21515",
    "CVE-2022-27778"
  );
  script_xref(name:"IAVA", value:"2022-A-0291");

  script_name(english:"Oracle MySQL Server (Jul 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of MySQL Server installed on the remote host are affected by multiple vulnerabilities as referenced in the
July 2022 CPU advisory.

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Packaging (OpenSSL)).
    Supported versions that are affected are 5.7.38 and prior. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in takeover of MySQL Server. (CVE-2022-1292)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Packaging (cURL)). Supported
    versions that are affected are 5.7.38 and prior. Easily exploitable vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks require
    human interaction from a person other than the attacker. Successful attacks of this vulnerability can result
    in unauthorized creation, deletion or modification access to critical data or all MySQL Server accessible
    data and unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
    Server. (CVE-2022-27778)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Compiling (zlib)). Supported
    versions that are affected are 5.7.38 and prior. Easily exploitable vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of
    this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash
    (complete DOS) of MySQL Server. (CVE-2018-25032)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2022 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1292");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/21");

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

mysql_check_version(fixed:'5.7.39', min:'5.7', severity:SECURITY_HOLE);
