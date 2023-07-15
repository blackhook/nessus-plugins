#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-15463.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79607);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2013-6497", "CVE-2014-9050");
  script_xref(name:"FEDORA", value:"2014-15463");

  script_name(english:"Fedora 19 : clamav-0.98.5-1.fc19 (2014-15463)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ClamAV 0.98.5 =============

ClamAV 0.98.5 also includes these new features and bug fixes :

  - Support for the XDP file format and extracting,
    decoding, and scanning PDF files within XDP files.
    Addition of shared library support for LLVM versions 3.1
    - 3.5 for the purpose of just-in-time(JIT) compilation
    of ClamAV bytecode signatures. Andreas Cadhalpun
    submitted the patch implementing this support.

    - Enhancements to the clambc command line utility to
      assist ClamAV bytecode signature authors by providing
      introspection into compiled bytecode programs.

    - Resolution of many of the warning messages from ClamAV
      compilation.

    - Improved detection of malicious PE files.

    - Security fix for ClamAV crash when using 'clamscan
      -a'. This issue was identified by Kurt Siefried of Red
      Hat.

    - Security fix for ClamAV crash when scanning
      maliciously crafted yoda's crypter files. This issue,
      as well as several other bugs fixed in this release,
      were identified by Damien Millescamp of Oppida.

    - ClamAV 0.98.5 now works with OpenSSL in FIPS compliant
      mode. Thanks to Reinhard Max for supplying the patch.

    - Bug fixes and other feature enhancements.

Please see the ChangeLog file or GIT log for further details.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1138101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1167139"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-November/144979.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f74658c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected clamav package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 Tenable Network Security, Inc.");
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
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"clamav-0.98.5-1.fc19")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav");
}