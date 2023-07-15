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
  script_id(61370);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-1178", "CVE-2012-2318", "CVE-2012-3374");

  script_name(english:"Scientific Linux Security Update : pidgin on SL5.x, SL6.x i386/x86_64 (20120719)");
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
"Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.

A flaw was found in the way the Pidgin MSN protocol plug-in processed
text that was not encoded in UTF-8. A remote attacker could use this
flaw to crash Pidgin by sending a specially crafted MSN message.
(CVE-2012-1178)

An input validation flaw was found in the way the Pidgin MSN protocol
plug-in handled MSN notification messages. A malicious server or a
remote attacker could use this flaw to crash Pidgin by sending a
specially crafted MSN notification message. (CVE-2012-2318)

A buffer overflow flaw was found in the Pidgin MXit protocol plug-in.
A remote attacker could use this flaw to crash Pidgin by sending a
MXit message containing specially crafted emoticon tags.
(CVE-2012-3374)

All Pidgin users should upgrade to these updated packages, which
contain backported patches to resolve these issues. Pidgin must be
restarted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=5724
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b520df42"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libpurple-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pidgin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pidgin-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/19");
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
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"finch-2.6.6-11.el5.4")) flag++;
if (rpm_check(release:"SL5", reference:"finch-devel-2.6.6-11.el5.4")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-2.6.6-11.el5.4")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-devel-2.6.6-11.el5.4")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-perl-2.6.6-11.el5.4")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-tcl-2.6.6-11.el5.4")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-2.6.6-11.el5.4")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-debuginfo-2.6.6-11.el5.4")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-devel-2.6.6-11.el5.4")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-perl-2.6.6-11.el5.4")) flag++;

if (rpm_check(release:"SL6", reference:"finch-2.7.9-5.el6.2")) flag++;
if (rpm_check(release:"SL6", reference:"finch-devel-2.7.9-5.el6.2")) flag++;
if (rpm_check(release:"SL6", reference:"libpurple-2.7.9-5.el6.2")) flag++;
if (rpm_check(release:"SL6", reference:"libpurple-devel-2.7.9-5.el6.2")) flag++;
if (rpm_check(release:"SL6", reference:"libpurple-perl-2.7.9-5.el6.2")) flag++;
if (rpm_check(release:"SL6", reference:"libpurple-tcl-2.7.9-5.el6.2")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-2.7.9-5.el6.2")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-debuginfo-2.7.9-5.el6.2")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-devel-2.7.9-5.el6.2")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-docs-2.7.9-5.el6.2")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-perl-2.7.9-5.el6.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / finch-devel / libpurple / libpurple-devel / libpurple-perl / etc");
}
