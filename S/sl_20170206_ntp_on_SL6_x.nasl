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
  script_id(97039);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-7426", "CVE-2016-7429", "CVE-2016-7433", "CVE-2016-9310", "CVE-2016-9311");

  script_name(english:"Scientific Linux Security Update : ntp on SL6.x, SL7.x i386/x86_64 (20170206)");
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
"Security Fix(es) :

  - It was found that when ntp is configured with rate
    limiting for all associations the limits are also
    applied to responses received from its configured
    sources. A remote attacker who knows the sources can
    cause a denial of service by preventing ntpd from
    accepting valid responses from its sources.
    (CVE-2016-7426)

  - A flaw was found in the control mode functionality of
    ntpd. A remote attacker could send a crafted control
    mode packet which could lead to information disclosure
    or result in DDoS amplification attacks. (CVE-2016-9310)

  - A flaw was found in the way ntpd implemented the trap
    service. A remote attacker could send a specially
    crafted packet to cause a NULL pointer dereference that
    will crash ntpd, resulting in a denial of service.
    (CVE-2016-9311)

  - A flaw was found in the way ntpd running on a host with
    multiple network interfaces handled certain server
    responses. A remote attacker could use this flaw which
    would cause ntpd to not synchronize with the source.
    (CVE-2016-7429)

  - A flaw was found in the way ntpd calculated the root
    delay. A remote attacker could send a specially crafted
    spoofed packet to cause denial of service or in some
    special cases even crash. (CVE-2016-7433)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1702&L=scientific-linux-errata&F=&S=&P=1332
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b70acf84"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ntp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:sntp");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"ntp-4.2.6p5-10.el6_8.2")) flag++;
if (rpm_check(release:"SL6", reference:"ntp-debuginfo-4.2.6p5-10.el6_8.2")) flag++;
if (rpm_check(release:"SL6", reference:"ntp-doc-4.2.6p5-10.el6_8.2")) flag++;
if (rpm_check(release:"SL6", reference:"ntp-perl-4.2.6p5-10.el6_8.2")) flag++;
if (rpm_check(release:"SL6", reference:"ntpdate-4.2.6p5-10.el6_8.2")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ntp-4.2.6p5-25.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ntp-debuginfo-4.2.6p5-25.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"ntp-doc-4.2.6p5-25.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"ntp-perl-4.2.6p5-25.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ntpdate-4.2.6p5-25.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sntp-4.2.6p5-25.el7_3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp / ntp-debuginfo / ntp-doc / ntp-perl / ntpdate / sntp");
}
