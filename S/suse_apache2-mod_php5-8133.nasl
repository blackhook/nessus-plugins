#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59445);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-2335", "CVE-2012-2336");

  script_name(english:"SuSE 10 Security Update : PHP5 (ZYPP Patch Number 8133)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"PHP5 was updated with incremental fixes to the previous update :

  - Additional unsafe cgi wrapper scripts are also fixed
    now. (CVE-2012-2335)

  - Even more commandline option handling is filtered, which
    could lead to crashes of the php interpreter.
    (CVE-2012-2336)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2335.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2336.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8133.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES10", sp:4, reference:"apache2-mod_php5-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-bcmath-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-bz2-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-calendar-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-ctype-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-curl-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-dba-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-dbase-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-devel-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-dom-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-exif-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-fastcgi-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-ftp-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-gd-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-gettext-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-gmp-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-hash-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-iconv-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-imap-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-json-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-ldap-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-mbstring-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-mcrypt-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-mhash-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-mysql-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-ncurses-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-odbc-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-openssl-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-pcntl-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-pdo-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-pear-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-pgsql-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-posix-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-pspell-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-shmop-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-snmp-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-soap-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-sockets-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-sqlite-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-suhosin-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-sysvmsg-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-sysvsem-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-sysvshm-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-tokenizer-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-wddx-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-xmlreader-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-xmlrpc-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-xsl-5.2.14-0.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"php5-zlib-5.2.14-0.34.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
