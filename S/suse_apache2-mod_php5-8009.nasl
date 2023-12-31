#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58480);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2011-4153", "CVE-2011-4885", "CVE-2012-0057", "CVE-2012-0781", "CVE-2012-0788", "CVE-2012-0789", "CVE-2012-0807", "CVE-2012-0830", "CVE-2012-0831");
  script_xref(name:"TRA", value:"TRA-2012-01");

  script_name(english:"SuSE 10 Security Update : PHP5 (ZYPP Patch Number 8009)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of php5 fixes multiple security flaws :

  - missing checks of return values could allow remote
    attackers to cause a denial of service (NULL pointer
    dereference). (CVE-2011-4153)

  - denial of service via hash collisions. (CVE-2011-4885)

  - specially crafted XSLT stylesheets could allow remote
    attackers to create arbitrary files with arbitrary
    content. (CVE-2012-0057)

  - remote attackers can cause a denial of service via
    specially crafted input to an application that attempts
    to perform Tidy::diagnose operations. (CVE-2012-0781)

  - applications that use a PDO driver were prone to denial
    of service flaws which could be exploited remotely.
    (CVE-2012-0788)

  - memory leak in the timezone functionality could allow
    remote attackers to cause a denial of service (memory
    consumption). (CVE-2012-0789)

  - a stack-based buffer overflow in php5's Suhosin
    extension could allow remote attackers to execute
    arbitrary code via a long string that is used in a
    Set-Cookie HTTP header. (CVE-2012-0807)

  - this fixes an incorrect fix for CVE-2011-4885 which
    could allow remote attackers to execute arbitrary code
    via a request containing a large number of variables.
    (CVE-2012-0830)

  - temporary changes to the magic_quotes_gpc directive
    during the importing of environment variables is not
    properly performed which makes it easier for remote
    attackers to conduct SQL injections. (CVE-2012-0831)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4153.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4885.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0057.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0781.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0788.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0789.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0807.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0830.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0831.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2012-01"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8009.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLES10", sp:4, reference:"apache2-mod_php5-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-bcmath-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-bz2-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-calendar-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-ctype-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-curl-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-dba-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-dbase-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-devel-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-dom-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-exif-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-fastcgi-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-ftp-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-gd-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-gettext-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-gmp-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-hash-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-iconv-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-imap-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-json-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-ldap-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-mbstring-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-mcrypt-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-mhash-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-mysql-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-ncurses-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-odbc-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-openssl-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-pcntl-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-pdo-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-pear-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-pgsql-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-posix-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-pspell-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-shmop-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-snmp-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-soap-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-sockets-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-sqlite-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-suhosin-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-sysvmsg-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-sysvsem-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-sysvshm-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-tokenizer-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-wddx-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-xmlreader-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-xmlrpc-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-xsl-5.2.14-0.26.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-zlib-5.2.14-0.26.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
