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
  script_id(79229);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-6053", "CVE-2014-6054", "CVE-2014-6055");

  script_name(english:"Scientific Linux Security Update : kdenetwork on SL7.x x86_64 (20141111)");
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
"A NULL pointer dereference flaw was found in the way LibVNCServer
handled certain ClientCutText message. A remote attacker could use
this flaw to crash the VNC server by sending a specially crafted
ClientCutText message from a VNC client. (CVE-2014-6053)

A divide-by-zero flaw was found in the way LibVNCServer handled the
scaling factor when it was set to '0'. A remote attacker could use
this flaw to crash the VNC server using a malicious VNC client.
(CVE-2014-6054)

Two stack-based buffer overflow flaws were found in the way
LibVNCServer handled file transfers. A remote attacker could use this
flaw to crash the VNC server using a malicious VNC client.
(CVE-2014-6055)

Note: Prior to this update, the kdenetwork packages used an embedded
copy of the LibVNCServer library. With this update, the kdenetwork
packages have been modified to use the system LibVNCServer packages.
Therefore, the update provided by SLSA-2014:1826 must be installed to
fully address the issues in krfb described above.

All running instances of the krfb server must be restarted for this
update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1411&L=scientific-linux-errata&T=0&P=2944
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf5d8bed"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdenetwork-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdenetwork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdenetwork-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdenetwork-fileshare-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdenetwork-kdnssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdenetwork-kget");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdenetwork-kget-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdenetwork-kopete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdenetwork-kopete-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdenetwork-kopete-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdenetwork-krdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdenetwork-krdc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdenetwork-krdc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdenetwork-krfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdenetwork-krfb-libs");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", reference:"kdenetwork-common-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-debuginfo-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", reference:"kdenetwork-devel-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-fileshare-samba-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-kdnssd-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-kget-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-kget-libs-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-kopete-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-kopete-devel-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-kopete-libs-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-krdc-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-krdc-devel-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-krdc-libs-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-krfb-4.10.5-8.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdenetwork-krfb-libs-4.10.5-8.el7_0")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdenetwork / kdenetwork-common / kdenetwork-debuginfo / etc");
}
