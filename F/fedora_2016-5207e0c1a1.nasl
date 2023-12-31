#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-5207e0c1a1.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(89542);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2016-5207e0c1a1");

  script_name(english:"Fedora 22 : php-5.6.17-1.fc22 (2016-5207e0c1a1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"07 Jan 2016, **PHP 5.6.17** **Core:** * Fixed bug php#66909 (configure
fails utf8_to_mutf7 test). (Michael Orlitzky) * Fixed bug php#70958
(Invalid opcode while using ::class as trait method paramater default
value). (Laruence) * Fixed bug php#70957 (self::class can not be
resolved with reflection for abstract class). (Laruence) * Fixed bug
php#70944 (try{ } finally{} can create infinite chains of exceptions).
(Laruence) * Fixed bug php#61751 (SAPI build problem on AIX: Undefined
symbol: php_register_internal_extensions). (Lior Kaplan) **FPM:** *
Fixed bug php#70755 (fpm_log.c memory leak and buffer overflow).
(Stas) **GD:** * Fixed bug php#70976 (Memory Read via
gdImageRotateInterpolated Array Index Out of Bounds). (emmanuel dot
law at gmail dot com). **Mysqlnd:** * Fixed bug php#68077 (LOAD DATA
LOCAL INFILE / open_basedir restriction). (Laruence) **SOAP:** * Fixed
bug php#70900 (SoapClient systematic out of memory error). (Dmitry)
**Standard:** * Fixed bug php#70960 (ReflectionFunction for
array_unique returns wrong number of parameters). (Laruence)
**PDO_Firebird:** * Fixed bug php#60052 (Integer returned as a 64bit
integer on X64_86). (Mariuz) **WDDX:** * Fixed bug php#70661 (Use
After Free Vulnerability in WDDX Packet Deserialization).
(taoguangchen at icloud dot com) * Fixed bug php#70741 (Session WDDX
Packet Deserialization Type Confusion Vulnerability). (taoguangchen at
icloud dot com) **XMLRPC:** * Fixed bug php#70728 (Type Confusion
Vulnerability in PHP_to_XMLRPC_worker()). (Julien)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1297710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1297720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1297726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1297730"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-January/175617.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7ab47e9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"php-5.6.17-1.fc22")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
