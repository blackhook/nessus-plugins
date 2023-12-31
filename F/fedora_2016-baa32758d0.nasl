#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-baa32758d0.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(89886);
  script_version("2.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2016-baa32758d0");

  script_name(english:"Fedora 22 : php-5.6.19-1.fc22 (2016-baa32758d0)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"03 Mar 2016, **PHP 5.6.19** **CLI server:** * Fixed bug php#71559
(Built-in HTTP server, we can download file in web by bug). (Johannes,
Anatol) **CURL:**

  - Fixed bug php#71523 (Copied handle with new option
    CURLOPT_HTTPHEADER crashes while curl_multi_exec).
    (Laruence) **Date:** * Fixed bug php#68078 (Datetime
    comparisons ignore microseconds). (Willem-Jan
    Zijderveld) * Fixed bug php#71525 (Calls to date_modify
    will mutate timelib_rel_time, causing date_date_set
    issues). (Sean DuBois) **Fileinfo:** * Fixed bug
    php#71434 (finfo throws notice for specific python
    file). (Laruence) **FPM:** * Fixed bug php#62172 (FPM
    not working with Apache httpd 2.4 balancer/fcgi setup).
    (Matt Haught, Remi) **Opcache:** * Fixed bug php#71584
    (Possible use-after-free of ZCG(cwd) in Zend Opcache).
    (Yussuf Khalil) **PDO MySQL:** * Fixed bug php#71569
    (#70389 fix causes segmentation fault). (Nikita)
    **Phar:** * Fixed bug php#71498 (Out- of-Bound Read in
    phar_parse_zipfile()). (Stas) **Standard:** * Fixed bug
    php#70720 (strip_tags improper php code parsing).
    (Julien) **WDDX:** * Fixed bug php#71587 (Use-After-Free
    / Double-Free in WDDX Deserialize). (Stas) **XSL:** *
    Fixed bug php#71540 (NULL pointer dereference in
    xsl_ext_function_php()). (Stas) **Zip:** * Fixed bug
    php#71561 (NULL pointer dereference in Zip::ExtractTo).
    (Laruence)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-March/178773.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?177dc5db"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/14");
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
if (rpm_check(release:"FC22", reference:"php-5.6.19-1.fc22")) flag++;


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
