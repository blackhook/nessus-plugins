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
  script_id(96280);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-7030", "CVE-2016-9575");

  script_name(english:"Scientific Linux Security Update : ipa on SL7.x x86_64 (20170102)");
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

  - It was discovered that the default IdM password policies
    that lock out accounts after a certain number of failed
    login attempts were also applied to host and service
    accounts. A remote unauthenticated user could use this
    flaw to cause a denial of service attack against
    kerberized services. (CVE-2016-7030)

  - It was found that IdM's certprofile-mod command did not
    properly check the user's permissions while modifying
    certificate profiles. An authenticated, unprivileged
    attacker could use this flaw to modify profiles to issue
    certificates with arbitrary naming or key usage
    information and subsequently use such certificates for
    other attacks. (CVE-2016-9575)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1701&L=scientific-linux-errata&F=&S=&P=78
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2c09c3aa"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python2-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python2-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python2-ipaserver");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/04");
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
if (rpm_check(release:"SL7", reference:"ipa-admintools-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-client-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-client-common-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-common-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-debuginfo-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-python-compat-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-server-common-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-server-dns-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", reference:"python2-ipaclient-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", reference:"python2-ipalib-4.4.0-14.sl7_3.1.1")) flag++;
if (rpm_check(release:"SL7", reference:"python2-ipaserver-4.4.0-14.sl7_3.1.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-admintools / ipa-client / ipa-client-common / ipa-common / etc");
}
