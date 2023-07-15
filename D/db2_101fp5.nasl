#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84826);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2014-0919",
    "CVE-2014-3094",
    "CVE-2014-3095",
    "CVE-2014-6159",
    "CVE-2014-6209",
    "CVE-2014-6210",
    "CVE-2014-8901",
    "CVE-2014-8910",
    "CVE-2015-0138",
    "CVE-2015-0157",
    "CVE-2015-0197",
    "CVE-2015-0198",
    "CVE-2015-0199",
    "CVE-2015-1883",
    "CVE-2015-1922",
    "CVE-2015-1935",
    "CVE-2015-2808"
  );
  script_bugtraq_id(
    69546,
    69550,
    71006,
    71729,
    71730,
    71734,
    73278,
    73282,
    73283,
    73326,
    73684,
    74217,
    75908,
    75911,
    75946,
    75947,
    75949
  );

  script_name(english:"IBM DB2 10.1 < Fix Pack 5 Multiple Vulnerabilities (Bar Mitzvah)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 10.1 running on
the remote host is prior to Fix Pack 5. It is, therefore, affected by
multiple vulnerabilities :

  - An unspecified flaw exists in the monitoring or audit
    facility due to passwords being stored when handling
    specially crafted commands. A remote, authenticated
    attacker can exploit this to access sensitive
    information. (CVE-2014-0919)

  - A stack-based buffer overflow condition exists due to
    improper validation of user-supplied input when handling
    crafted ALTER MODULE statements. A remote, authenticated
    attacker can exploit this to cause a denial of service
    or execute arbitrary code. (CVE-2014-3094)

  - A flaw exists when handling a crafted UNION clause in a
    subquery of a SELECT statement. A remote, authenticated
    attacker can exploit this to cause a denial of service.
    (CVE-2014-3095)

  - A denial of service vulnerability exists when immediate
    AUTO_REVAL is enabled. A remote, authenticated attacker
    can exploit this, via a crafted ALTER TABLE statement,
    to crash the server. (CVE-2014-6159)

  - A denial of service vulnerability exists when handling
    an identity column within a crafted ALTER TABLE
    statement. A remote, authenticated attacker can exploit
    this vulnerability to crash the server. (CVE-2014-6209)

  - A denial of service vulnerability exists when handling
    multiple ALTER TABLE statements specifying the same
    column. A remote, authenticated attacker can exploit
    this vulnerability to crash the server. (CVE-2014-6210)

  - A flaw exists that is triggered when handling specially
    crafted XML queries. A remote, authenticated attacker
    can exploit this to cause a consumption of resources,
    resulting in a denial of service. (CVE-2014-8901)

  - An unspecified error exists during the handling of
    SELECT statements with XML/XSLT functions that allows a
    remote attacker to gain access to arbitrary files.
    (CVE-2014-8910)

  - A flaw exists in the IBM Global Security Kit (GSKit)
    when handling RSA temporary keys in a non-export RSA key
    exchange ciphersuite. A man-in-the-middle attacker can
    exploit this to downgrade the session security to use
    weaker EXPORT_RSA ciphers, thus allowing the attacker to
    more easily monitor or tamper with the encrypted stream.
    (CVE-2015-0138)

  - A flaw exists in the LUW component when handling SQL
    statements with unspecified Scaler functions. A remote,
    authenticated attacker can exploit this to cause a
    denial of service. (CVE-2015-0157)

  - An unspecified flaw in the General Parallel File System
    (GPFS) allows a local attacker to gain root privileges.
    (CVE-2015-0197)

  - A flaw exists in the General Parallel File System
    (GPFS), related to certain cipherList configurations,
    that allows a remote attacker, using specially crafted
    data, to bypass authentication and execute arbitrary
    programs with root privileges. (CVE-2015-0198)

  - A denial of service vulnerability exists in the General
    Parallel File System (GPFS) that allows a local attacker
    to corrupt kernel memory by sending crafted ioctl
    character device calls to the mmfslinux kernel module.
    (CVE-2015-0199)

  - An information disclosure vulnerability exists in the
    automated maintenance feature. An attacker with elevated
    privileges can exploit this issue by manipulating a
    stored procedure, resulting in the disclosure of
    arbitrary files owned by the DB2 fenced ID on UNIX/Linux
    or the administrator on Windows. (CVE-2015-1883)

  - A flaw exists in the Data Movement feature when handling
    specially crafted queries. An authenticated, remote
    attacker can exploit this to delete database rows from a
    table without having the appropriate privileges.
    (CVE-2015-1922)

  - An unspecified flaw exists when handling SQL statements
    with LUW Scaler functions. An authenticated, remote
    attacker can exploit this to run arbitrary code, under
    the privileges of the DB2 instance owner, or to cause a
    denial of service. (CVE-2015-1935)

  - A security feature bypass vulnerability exists, known as
    Bar Mitzvah, due to improper combination of state data
    with key data by the RC4 cipher algorithm during the
    initialization phase. A man-in-the-middle attacker can
    exploit this, via a brute-force attack using LSB values,
    to decrypt the traffic. (CVE-2015-2808)

  - A flaw exists when handling 'SUM' or 'GROUP BY' queries
    with a 'SUBSELECT' that contains 'unnest'. An
    authenticated, remote attacker can exploit this to cause
    a denial of service condition.

  - A use-after-free error exists in the CLI application due
    to improper validation of user-supplied input when
    handling client disconnects. An unauthenticated, remote
    attacker can exploit this to corrupt memory, resulting
    in a denial of service condition or the execution of
    arbitrary code.

  - A denial of service vulnerability exists due to an
    unspecified flaw in the sqldRemoveCachedTableEntry()
    function. An authenticated, remote attacker can exploit
    this to crash a DB2 instance.

  - An out-of-bounds write error exists due to improper
    validation of user-supplied input when handling the
    Partial Aggregation Operators (PED, PEA). A remote,
    authenticated attacker can exploit this to corrupt
    memory, resulting in a denial of service condition.

  - An integrity flaw exists due to insecure file
    permissions for the STMM log file. A local attacker can
    exploit this to manipulate the logs.

  - A denial of service vulnerability exists in the
    sqlex_find_group() function when returning a cumulative
    group name greater than 64K. An authenticated, remote
    attacker can exploit this to crash the server.

  - A flaw exists in the sqlsBinSortPopulateRecPointers()
    function due to improper validation of user-supplied
    input when performing resettable sorts. A remote,
    authenticated attacker can exploit this to corrupt
    memory, resulting in a denial of service.

  - A flaw exists that is triggered when handling 'INSERT
    INTO' statements. An authenticated, remote attacker can
    exploit this to crash DB2 when the target is a generated
    table created by a values clause containing multiple
    rows.

  - A flaw exists when invoking runstats against a user
    temporary table when the index clause explicitly
    specifies index names but omits the index schema name.
    An authenticated, remote attacker can exploit this to
    cause a denial of service.

  - A flaw exists in the DRDA communication protocol due to
    improper parsing of split DRDA messages under certain
    circumstances. An authenticated, remote attacker can
    exploit this to cause a large memory overwrite,
    resulting in a denial of service condition or the
    execution of arbitrary code.

  - An information disclosure vulnerability exists due to
    improper block cipher padding by TLSv1 when using Cipher
    Block Chaining (CBC) mode. A remote attacker, via an
    'Oracle Padding' side channel attack, can exploit this
    vulnerability to gain access to sensitive information.
    Note that this is a variation of the POODLE attack.
    (NO CVE)");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21697987");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21697988");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21698308");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21902662");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21959650");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21902661");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT06419");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT05791");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT05128");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT07811");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT07735");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT06800");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT03088");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT03086");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT02983");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT02530");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT02593");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT02646");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT05652");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT05074");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT05647");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT05939");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT06350");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT06354");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT07108");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT08080");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT07553");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT07646");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT08112");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT08525");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT08536");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT08543");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21610582");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg24040170");
  # https://www.blackhat.com/docs/asia-15/materials/asia-15-Mantin-Bar-Mitzvah-Attack-Breaking-SSL-With-13-Year-Old-RC4-Weakness-wp.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bbf45ac");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/12/08/poodleagain.html");
  script_set_attribute(attribute:"solution", value:
"Apply IBM DB2 version 10.1 Fix Pack 5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("db2_report_func.inc");

port = get_service(svc:"db2das", default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/" + port + "/Level");
if (level !~ "^10\.1\.") audit(AUDIT_NOT_LISTEN, "DB2 10.1", port);

platform = get_kb_item_or_exit("DB2/"+port+"/Platform");
platform_name = get_kb_item("DB2/"+port+"/Platform_Name");
if (isnull(platform_name))
{
  platform_name = platform;
  report_phrase = "platform " + platform;
}
else
  report_phrase = platform_name;


vuln = FALSE;
# Windows 32-bit/64-bit
if (platform == 5 || platform == 23)
{
  fixed_level = '10.1.500.397';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    vuln = TRUE;
}
# Others
else if (
  # Linux, 2.6 kernel 32/64-bit
  platform == 18 ||
  platform == 30 ||
  # AIX
  platform == 20
)
{
  fixed_level = '10.1.0.5';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    vuln = TRUE;
}
else
{
  info =
    'Nessus does not support version checks against ' + report_phrase + '.\n' +
    'To help us better identify vulnerable versions, please send the platform\n' +
    'number along with details about the platform, including the operating system\n' +
    'version, CPU architecture, and DB2 version to db2-platform-info@nessus.org.\n';
  exit(1, info);
}

if (vuln)
{
  report_db2(
      severity        : SECURITY_HOLE,
      port            : port,
      platform_name   : platform_name,
      installed_level : level,
      fixed_level     : fixed_level);
}
else audit(AUDIT_LISTEN_NOT_VULN, "DB2", port, level);
