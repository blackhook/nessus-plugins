#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(60444);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-4782", "CVE-2007-5898", "CVE-2007-5899", "CVE-2008-2051", "CVE-2008-2107", "CVE-2008-2108");

  script_name(english:"Scientific Linux Security Update : php on SL4.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the PHP escapeshellcmd() function did not
properly escape multi-byte characters which are not valid in the
locale used by the script. This could allow an attacker to bypass
quoting restrictions imposed by escapeshellcmd() and execute arbitrary
commands if the PHP script was using certain locales. Scripts using
the default UTF-8 locale are not affected by this issue.
(CVE-2008-2051)

The PHP functions htmlentities() and htmlspecialchars() did not
properly recognize partial multi-byte sequences. Certain sequences of
bytes could be passed through these functions without being correctly
HTML-escaped. Depending on the browser being used, an attacker could
use this flaw to conduct cross-site scripting attacks. (CVE-2007-5898)

A PHP script which used the transparent session ID configuration
option, or which used the output_add_rewrite_var() function, could
leak session identifiers to external websites. If a page included an
HTML form with an ACTION attribute referencing a non-local URL, the
user's session ID would be included in the form data passed to that
URL. (CVE-2007-5899)

It was discovered that the PHP fnmatch() function did not restrict the
length of the string argument. An attacker could use this flaw to
crash the PHP interpreter where a script used fnmatch() on untrusted
input data. (CVE-2007-4782)

It was discovered that PHP did not properly seed its pseudo-random
number generator used by functions such as rand() and mt_rand(),
possibly allowing an attacker to easily predict the generated
pseudo-random values. (CVE-2008-2107, CVE-2008-2108)

As well, these updated packages fix the following bug :

  - after 2008-01-01, when using PEAR version 1.3.6 or
    older, it was not possible to use the PHP Extension and
    Application Repository (PEAR) to upgrade or install
    packages. In these updated packages, PEAR has been
    upgraded to version 1.4.9, which restores support for
    the current pear.php.net update server. The following
    changes were made to the PEAR packages included in
    php-pear: Console_Getopt and Archive_Tar are now
    included by default, and XML_RPC has been upgraded to
    version 1.5.0."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind0807&L=scientific-linux-errata&T=0&P=1437
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07acb740"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 189, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL4", reference:"php-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"SL4", reference:"php-devel-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"SL4", reference:"php-domxml-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"SL4", reference:"php-gd-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"SL4", reference:"php-imap-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"SL4", reference:"php-ldap-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"SL4", reference:"php-mbstring-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"SL4", reference:"php-mysql-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"SL4", reference:"php-ncurses-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"SL4", reference:"php-odbc-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"SL4", reference:"php-pear-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"SL4", reference:"php-pgsql-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"SL4", reference:"php-snmp-4.3.9-3.22.12")) flag++;
if (rpm_check(release:"SL4", reference:"php-xmlrpc-4.3.9-3.22.12")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
