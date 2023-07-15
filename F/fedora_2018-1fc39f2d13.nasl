#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-1fc39f2d13.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118159);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-14679", "CVE-2018-14680", "CVE-2018-14681", "CVE-2018-14682", "CVE-2018-15378");
  script_xref(name:"FEDORA", value:"2018-1fc39f2d13");

  script_name(english:"Fedora 27 : clamav (2018-1fc39f2d13)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ClamAV 0.100.2 has been released! This is a patch release to address
several vulnerabilities.

Fixes for the following ClamAV vulnerabilities: CVE-2018-15378:
Vulnerability in ClamAV's MEW unpacking feature that could allow an
unauthenticated, remote attacker to cause a denial-of-service (DoS)
condition on an affected device. Reported by Secunia Research at
Flexera. Fix for a two-byte buffer over-read bug in ClamAV's PDF
parsing code. Reported by Alex Gaynor. Fixes for the following
vulnerabilities in bundled third-party libraries: CVE-2018-14680: An
issue was discovered in mspack/chmd.c in libmspack before 0.7alpha. It
does not reject blank CHM filenames. CVE-2018-14681: An issue was
discovered in kwajd_read_headers in mspack/kwajd.c in libmspack before
0.7alpha. Bad KWAJ file header extensions could cause a one- or
two-byte overwrite. CVE-2018-14682: An issue was discovered in
mspack/chmd.c in libmspack before 0.7alpha. There is an off-by-one
error in the TOLOWER() macro for CHM decompression. Additionally,
0.100.2 reverted 0.100.1's patch for CVE-2018-14679, and applied
libmspack's version of the fix in its place

Other changes: Some users have reported freshclam signature
update failures as a result of a delay between the time the
new signature database content is announced and the time
that the content-delivery-network has the content available
for download. To mitigate these errors, this patch release
includes some modifications to freshclam to make it more
lenient, and to reduce the time that freshclam will ignore a
mirror when it detects an issue. On-Access 'Extra Scanning,'
an opt-in minor feature of OnAccess scanning on Linux
systems, has been disabled due to a known issue with
resource cleanup OnAccessExtraScanning will be re-enabled in
a future release when the issue is resolved. In the
mean-time, users who enabled the feature in clamd.conf will
see a warning informing them that the feature is not active.
For details, click here.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-1fc39f2d13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected clamav package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:27");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^27([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 27", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC27", reference:"clamav-0.100.2-2.fc27")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav");
}
