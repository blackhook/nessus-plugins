#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129359);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2012-5615",
    "CVE-2014-0195",
    "CVE-2014-0198",
    "CVE-2014-0221",
    "CVE-2014-0224",
    "CVE-2014-3470",
    "CVE-2014-4274",
    "CVE-2014-4287",
    "CVE-2014-6463",
    "CVE-2014-6474",
    "CVE-2014-6478",
    "CVE-2014-6484",
    "CVE-2014-6489",
    "CVE-2014-6495",
    "CVE-2014-6505",
    "CVE-2014-6520",
    "CVE-2014-6530",
    "CVE-2014-6551",
    "CVE-2014-6564",
    "CVE-2015-0391"
  );
  script_bugtraq_id(
    56766,
    66801,
    67193,
    67898,
    67899,
    67900,
    67901,
    69732,
    70448,
    70455,
    70462,
    70486,
    70489,
    70496,
    70510,
    70511,
    70516,
    70517,
    70525,
    70532,
    72205
  );

  script_name(english:"MariaDB 10.0.0 < 10.0.13 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 10.0.13. It is, therefore, affected by multiple
vulnerabilities as referenced in the mariadb-10013-release-notes advisory, including the following:

  - A flaw in OpenSSL which fails to properly restrict
    processing of ChangeCipherSpec messages. A
    man-in-the-middle attacker can exploit this, via a
    crafted TLS handshake, to force the use of a
    zero-length master key in certain OpenSSL-to-OpenSSL
    communications, resulting in the session being hijacked
    and sensitive information being disclosed.
    (CVE-2014-0224)

 -  A buffer overflow error in OpenSSL related to invalid 
    DTLS fragment handling that can lead to execution of
    arbitrary code or denial of service. This is caused by
    improper validation on the fragment lengths in DTLS 
    ClientHello messages. (CVE-2014-0195)

  - An unspecified vulnerability in MariaDB Server related
    to CLIENT:MYSQLDUMP that allows remote, authenticated
    users to affect confidentiality, integrity, and
    availability. (CVE-2014-6530)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-10013-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.0.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0195");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-0224");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
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

mysql_check_version(variant: 'MariaDB', min:'10.0.0-MariaDB', fixed:make_list('10.0.13-MariaDB'), severity:SECURITY_WARNING);
