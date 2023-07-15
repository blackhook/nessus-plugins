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
  script_id(88175);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-8138");

  script_name(english:"Scientific Linux Security Update : ntp on SL6.x, SL7.x i386/x86_64 (20160125)");
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
"It was discovered that ntpd as a client did not correctly check the
originate timestamp in received packets. A remote attacker could use
this flaw to send a crafted packet to an ntpd client that would
effectively disable synchronization with the server, or push arbitrary
offset/delay measurements to modify the time on the client.
(CVE-2015-8138)

After installing the update, the ntpd daemon will restart
automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1601&L=scientific-linux-errata&F=&S=&P=11088
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?22438291"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ntp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sntp");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"ntp-4.2.6p5-5.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"ntp-debuginfo-4.2.6p5-5.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"ntp-doc-4.2.6p5-5.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"ntp-perl-4.2.6p5-5.el6_7.4")) flag++;
if (rpm_check(release:"SL6", reference:"ntpdate-4.2.6p5-5.el6_7.4")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ntp-4.2.6p5-22.el7_2.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ntp-debuginfo-4.2.6p5-22.el7_2.1")) flag++;
if (rpm_check(release:"SL7", reference:"ntp-doc-4.2.6p5-22.el7_2.1")) flag++;
if (rpm_check(release:"SL7", reference:"ntp-perl-4.2.6p5-22.el7_2.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ntpdate-4.2.6p5-22.el7_2.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sntp-4.2.6p5-22.el7_2.1")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp / ntp-debuginfo / ntp-doc / ntp-perl / ntpdate / sntp");
}
