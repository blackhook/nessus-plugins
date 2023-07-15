#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-d034538627.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106086);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"FEDORA", value:"2018-d034538627");

  script_name(english:"Fedora 27 : php (2018-d034538627)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**PHP version 7.1.13** (04 Jan 2018)

**Core:**

  - Fixed bug php#75573 (Segmentation fault in 7.1.12 and
    7.0.26). (Laruence)

  - Fixed bug php#75384 (PHP seems incompatible with
    OneDrive files on demand). (Anatol)

  - Fixed bug php#74862 (Unable to clone instance when
    private __clone defined). (Daniel Ciochiu)

  - Fixed bug php#75074 (php-process crash when is_file() is
    used with strings longer 260 chars). (Anatol)

**CLI Server:**

  - Fixed bug php#60471 (Random 'Invalid request (unexpected
    EOF)' using a router script). (SammyK)

  - Fixed bug php#73830 (Directory does not exist). (Anatol)

**FPM:**

  - Fixed bug php#64938 (libxml_disable_entity_loader
    setting is shared between requests). (Remi)

**Opcache:**

  - Fixed bug php#75608 ('Narrowing occurred during type
    inference' error). (Laruence, Dmitry)

  - Fixed bug php#75579 (Interned strings buffer overflow
    may cause crash). (Dmitry)

  - Fixed bug php#75570 ('Narrowing occurred during type
    inference' error). (Dmitry)

**PCRE:**

  - Fixed bug php#74183 (preg_last_error not returning error
    code after error). (Andrew Nester)

**Phar:**

  - Fixed bug php#74782 (remove file name from output to
    avoid XSS). (stas)

**Standard:**

  - Fixed bug php#75511 (fread not free unused buffer).
    (Laruence)

  - Fixed bug php#75514 (mt_rand returns value outside
    [$min,$max]+ on 32-bit) (Remi)

  - Fixed bug php#75535 (Inappropriately parsing HTTP
    response leads to PHP segment fault). (Nikita)

  - Fixed bug php#75409 (accept EFAULT in addition to ENOSYS
    as indicator that getrandom() is missing).
    (sarciszewski)

  - Fixed bug php#73124 (php_ini_scanned_files() not
    reporting correctly). (John Stevenson)

  - Fixed bug php#75574 (putenv does not work properly if
    parameter contains non-ASCII unicode character).
    (Anatol)

**Zip:**

  - Fixed bug php#75540 (Segfault with libzip 1.3.1). (Remi)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-d034538627"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:27");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/17");
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
if (rpm_check(release:"FC27", reference:"php-7.1.13-1.fc27")) flag++;


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
