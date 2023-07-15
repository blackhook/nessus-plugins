#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-6f37f99641.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111399);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"FEDORA", value:"2018-6f37f99641");

  script_name(english:"Fedora 27 : php (2018-6f37f99641)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**PHP version 7.1.20** (19 Jul 2018)

**Core:**

  - Fixed bug php#76534 (PHP hangs on 'illegal string offset
    on string references with an error handler). (Laruence)

  - Fixed bug php#76502 (Chain of mixed exceptions and
    errors does not serialize properly). (Nikita)

**Date:**

  - Fixed bug php#76462 (Undefined property:
    DateInterval::$f). (Anatol)

**exif:**

  - Fixed bug php#76423 (Int Overflow lead to Heap OverFlow
    in exif_thumbnail_extract of exif.c). (Stas) . Fixed bug
    php#76557 (heap-buffer-overflow (READ of size 48) while
    reading exif data). (Stas)

**FPM:**

  - Fixed bug php#73342 (Vulnerability in php-fpm by
    changing stdin to non-blocking). (Nikita)

**GMP:**

  - Fixed bug php#74670 (Integer Underflow when
    unserializing GMP and possible other classes). (Nikita)

**intl:**

  - Fixed bug php#76556 (get_debug_info handler for
    BreakIterator shows wrong type). (cmb)

**mbstring:**

  - Fixed bug php#76532 (Integer overflow and excessive
    memory usage in mb_strimwidth). (MarcusSchwarz)

**PGSQL:**

  - Fixed bug php#76548 (pg_fetch_result did not fetch the
    next row). (Anatol)

**phpdbg:**

  - Fix arginfo wrt. optional/required parameters. (cmb)

**Reflection:**

  - Fixed bug php#76536 (PHP crashes with core dump when
    throwing exception in error handler). (Laruence)

  - Fixed bug php#75231 (ReflectionProperty#getValue()
    incorrectly works with inherited classes). (Nikita)

**Standard:**

  - Fixed bug php#76505 (array_merge_recursive() is
    duplicating sub-array keys). (Laruence)

  - Fixed bug php#71848 (getimagesize with $imageinfo
    returns false). (cmb)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-6f37f99641"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:27");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/30");
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
if (rpm_check(release:"FC27", reference:"php-7.1.20-1.fc27")) flag++;


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
