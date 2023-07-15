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
  script_id(87838);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-7575");

  script_name(english:"Scientific Linux Security Update : gnutls on SL6.x, SL7.x i386/x86_64 (20160107) (SLOTH)");
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
"A flaw was found in the way TLS 1.2 could use the MD5 hash function
for signing ServerKeyExchange and Client Authentication packets during
a TLS handshake. A man-in-the-middle attacker able to force a TLS
connection to use the MD5 hash function could use this flaw to conduct
collision attacks to impersonate a TLS server or an authenticated TLS
client. (CVE-2015-7575)

For the update to take effect, all applications linked to the GnuTLS
library must be restarted."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1601&L=scientific-linux-errata&F=&S=&P=2989
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0841dc49"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnutls-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnutls-dane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnutls-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnutls-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/11");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (rpm_check(release:"SL6", reference:"gnutls-2.8.5-19.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"gnutls-debuginfo-2.8.5-19.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"gnutls-devel-2.8.5-19.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"gnutls-guile-2.8.5-19.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"gnutls-utils-2.8.5-19.el6_7")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnutls-3.3.8-14.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnutls-c++-3.3.8-14.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnutls-dane-3.3.8-14.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnutls-debuginfo-3.3.8-14.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnutls-devel-3.3.8-14.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnutls-utils-3.3.8-14.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls / gnutls-c++ / gnutls-dane / gnutls-debuginfo / gnutls-devel / etc");
}
