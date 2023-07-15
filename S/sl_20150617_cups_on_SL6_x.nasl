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
  script_id(84259);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-9679", "CVE-2015-1158", "CVE-2015-1159");

  script_name(english:"Scientific Linux Security Update : cups on SL6.x, SL7.x i386/x86_64 (20150617)");
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
"A string reference count bug was found in cupsd, causing premature
freeing of string objects. An attacker can submit a malicious print
job that exploits this flaw to dismantle ACLs protecting privileged
operations, allowing a replacement configuration file to be uploaded
which in turn allows the attacker to run arbitrary code in the CUPS
server (CVE-2015-1158)

A cross-site scripting flaw was found in the cups web templating
engine. An attacker could use this flaw to bypass the default
configuration settings that bind the CUPS scheduler to the 'localhost'
or loopback interface. (CVE-2015-1159)

An integer overflow leading to a heap-based buffer overflow was found
in the way cups handled compressed raster image files. An attacker
could create a specially crafted image file, which when passed via the
cups Raster filter, could cause the cups filter to crash.
(CVE-2014-9679)

After installing this update, the cupsd daemon will be restarted
automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1506&L=scientific-linux-errata&F=&S=&P=11940
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0667d822"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cups-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cups-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cups-ipptool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cups-php");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"cups-1.4.2-67.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"cups-debuginfo-1.4.2-67.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"cups-devel-1.4.2-67.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"cups-libs-1.4.2-67.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"cups-lpd-1.4.2-67.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"cups-php-1.4.2-67.el6_6.1")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"cups-1.6.3-17.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"cups-client-1.6.3-17.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"cups-debuginfo-1.6.3-17.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"cups-devel-1.6.3-17.el7_1.1")) flag++;
if (rpm_check(release:"SL7", reference:"cups-filesystem-1.6.3-17.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"cups-ipptool-1.6.3-17.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"cups-libs-1.6.3-17.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"cups-lpd-1.6.3-17.el7_1.1")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-client / cups-debuginfo / cups-devel / cups-filesystem / etc");
}
