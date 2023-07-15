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
  script_id(70603);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-6085", "CVE-2013-4351", "CVE-2013-4402");

  script_name(english:"Scientific Linux Security Update : gnupg2 on SL5.x, SL6.x i386/x86_64 (20131024)");
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
"A denial of service flaw was found in the way GnuPG parsed certain
compressed OpenPGP packets. An attacker could use this flaw to send
specially crafted input data to GnuPG, making GnuPG enter an infinite
loop when parsing data. (CVE-2013-4402)

It was found that importing a corrupted public key into a GnuPG
keyring database corrupted that keyring. An attacker could use this
flaw to trick a local user into importing a specially crafted public
key into their keyring database, causing the keyring to be corrupted
and preventing its further use. (CVE-2012-6085)

It was found that GnuPG did not properly interpret the key flags in a
PGP key packet. GPG could accept a key for uses not indicated by its
holder. (CVE-2013-4351)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1310&L=scientific-linux-errata&T=0&P=2885
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f14dc535"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected gnupg2, gnupg2-debuginfo and / or gnupg2-smime
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnupg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnupg2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnupg2-smime");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/25");
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
if (rpm_check(release:"SL5", reference:"gnupg2-2.0.10-6.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"gnupg2-debuginfo-2.0.10-6.el5_10")) flag++;

if (rpm_check(release:"SL6", reference:"gnupg2-2.0.14-6.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"gnupg2-debuginfo-2.0.14-6.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"gnupg2-smime-2.0.14-6.el6_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnupg2 / gnupg2-debuginfo / gnupg2-smime");
}
