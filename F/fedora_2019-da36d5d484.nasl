#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-da36d5d484.
#

include("compat.inc");

if (description)
{
  script_id(124045);
  script_version("1.2");
  script_cvs_date("Date: 2019/09/23 11:21:11");

  script_xref(name:"FEDORA", value:"2019-da36d5d484");

  script_name(english:"Fedora 29 : php (2019-da36d5d484)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**PHP version 7.2.17** (04 Apr 2019)

**Core:**

  - Fixed bug php#77738 (Nullptr deref in
    zend_compile_expr). (Laruence)

  - Fixed bug php#77660 (Segmentation fault on break
    2147483648). (Laruence)

  - Fixed bug php#77652 (Anonymous classes can lose their
    interface information). (Nikita)

  - Fixed bug php#77676 (Unable to run tests when building
    shared extension on AIX). (Kevin Adler)

**Bcmath:**

  - Fixed bug php#77742 (bcpow() implementation related to
    gcc compiler optimization). (Nikita)

**COM:**

  - Fixed bug php#77578 (Crash when php unload). (cmb)

**Date:**

  - Fixed bug php#50020 (DateInterval:createDateFromString()
    silently fails). (Derick)

  - Fixed bug php#75113 (Added DatePeriod::getRecurrences()
    method). (Ignace Nyamagana Butera)

**EXIF:**

  - Fixed bug php#77753 (Heap-buffer-overflow in
    php_ifd_get32s). (Stas)

  - Fixed bug php#77831 (Heap-buffer-overflow in
    exif_iif_add_value). (Stas)

**FPM:**

  - Fixed bug php#77677 (FPM fails to build on AIX due to
    missing WCOREDUMP). (Kevin Adler)

**GD:**

  - Fixed bug php#77700 (Writing truecolor images as GIF
    ignores interlace flag). (cmb)

**MySQLi:**

  - Fixed bug php#77597 (mysqli_fetch_field hangs scripts).
    (Nikita)

**Opcache:**

  - Fixed bug php#77691 (Opcache passes wrong value for
    inline array push assignments). (Nikita)

  - Fixed bug php#77743 (Incorrect pi node insertion for
    jmpznz with identical successors). (Nikita)

**phpdbg:**

  - Fixed bug php#77767 (phpdbg break cmd aliases listed in
    help do not match actual aliases). (Miriam Lauter)

**sodium:**

  - Fixed bug php#77646 (sign_detached() strings not
    terminated). (Frank)

**SQLite3:**

  - Added sqlite3.defensive INI directive. (BohwaZ)

**Standard:**

  - Fixed bug php#77664 (Segmentation fault when using
    undefined constant in custom wrapper). (Laruence)

  - Fixed bug php#77669 (Crash in extract() when overwriting
    extracted array). (Nikita)

  - Fixed bug php#76717 (var_export() does not create a
    parsable value for PHP_INT_MIN). (Nikita)

  - Fixed bug php#77765 (FTP stream wrapper should set the
    directory as executable). (Vlad Temian)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-da36d5d484"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^29([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 29", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC29", reference:"php-7.2.17-1.fc29")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
