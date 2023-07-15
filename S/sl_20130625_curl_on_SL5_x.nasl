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
  script_id(66982);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-2174");

  script_name(english:"Scientific Linux Security Update : curl on SL5.x, SL6.x i386/srpm/x86_64 (20130625)");
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
"A heap-based buffer overflow flaw was found in the way libcurl
unescaped URLs. A remote attacker could provide a specially crafted
URL that, when processed by an application using libcurl that handles
untrusted URLs, would possibly cause it to crash or, potentially,
execute arbitrary code. (CVE-2013-2174)

All running applications using libcurl must be restarted for the
update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1306&L=scientific-linux-errata&T=0&P=2344
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70c4d1b9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:curl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL5", reference:"curl-7.15.5-17.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"curl-debuginfo-7.15.5-17.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"curl-debuginfo-7.15.5-17.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"curl-devel-7.15.5-17.el5_9")) flag++;

if (rpm_check(release:"SL6", reference:"curl-7.19.7-37.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"curl-debuginfo-7.19.7-37.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"curl-debuginfo-7.19.7-37.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"libcurl-7.19.7-37.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"libcurl-devel-7.19.7-37.el6_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-debuginfo / curl-devel / libcurl / libcurl-devel");
}
