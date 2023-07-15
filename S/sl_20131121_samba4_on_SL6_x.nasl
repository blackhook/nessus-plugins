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
  script_id(71200);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-4124");

  script_name(english:"Scientific Linux Security Update : samba4 on SL6.x i386/x86_64 (20131121)");
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
"An integer overflow flaw was found in the way Samba handled an
Extended Attribute (EA) list provided by a client. A malicious client
could send a specially crafted EA list that triggered an overflow,
causing the server to loop and reprocess the list using an excessive
amount of memory. (CVE-2013-4124)

Note: This issue did not affect the default configuration of the Samba
server.

This update fixes the following bugs :

  - When Samba was installed in the build root directory,
    the RPM target might not have existed. Consequently, the
    find-debuginfo.sh script did not create symbolic links
    for the libwbclient.so.debug module associated with the
    target. With this update, the paths to the symbolic
    links are relative so that the symbolic links are now
    created correctly.

  - Previously, the samba4 packages were missing a
    dependency for the libreplace.so module which could lead
    to installation failures. With this update, the missing
    dependency has been added to the dependency list of the
    samba4 packages and installation now proceeds as
    expected."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=1058
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?823b7831"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba4-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/04");
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
if (rpm_check(release:"SL6", reference:"samba4-4.0.0-58.el6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-client-4.0.0-58.el6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-common-4.0.0-58.el6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-dc-4.0.0-58.el6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-dc-libs-4.0.0-58.el6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-debuginfo-4.0.0-58.el6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-devel-4.0.0-58.el6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-libs-4.0.0-58.el6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-pidl-4.0.0-58.el6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-python-4.0.0-58.el6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-swat-4.0.0-58.el6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-test-4.0.0-58.el6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-4.0.0-58.el6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-clients-4.0.0-58.el6.rc4")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-krb5-locator-4.0.0-58.el6.rc4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba4 / samba4-client / samba4-common / samba4-dc / samba4-dc-libs / etc");
}
