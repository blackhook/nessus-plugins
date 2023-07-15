#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-cdaaf6ea12.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104451);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2016-1283");
  script_xref(name:"FEDORA", value:"2017-cdaaf6ea12");

  script_name(english:"Fedora 25 : php (2017-cdaaf6ea12)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**PHP version 7.0.25** (26 Oct 2017)

**Core:**

  - Fixed bug php#75241 (NULL pointer dereference in
    zend_mm_alloc_small()). (Laruence)

  - Fixed bug php#75236 (infinite loop when printing an
    error-message). (Andrea)

  - Fixed bug php#75252 (Incorrect token formatting on two
    parse errors in one request). (Nikita)

  - Fixed bug php#75220 (Segfault when calling is_callable
    on parent). (andrewnester)

  - Fixed bug php#75290 (debug info of Closures of internal
    functions contain garbage argument names). (Andrea)

**Apache2Handler:**

  - Fixed bug php#75311 (error: 'zend_hash_key' has no
    member named 'arKey' in apache2handler). (mcarbonneaux)

**Date:**

  - Fixed bug php#75055 (Out-Of-Bounds Read in
    timelib_meridian()). (Derick)

**Intl:**

  - Fixed bug php#75318 (The parameter of
    UConverter::getAliases() is not optional). (cmb)

**mcrypt:**

  - Fixed bug php#72535 (arcfour encryption stream filter
    crashes php). (Leigh)

**PCRE:**

  - Fixed bug php#75207 (applied upstream patch for
    CVE-2016-1283). (Anatol)

**litespeed:**

  - Fixed bug php#75248 (Binary directory doesn't get
    created when building only litespeed SAPI). (petk)

  - Fixed bug php#75251 (Missing program prefix and suffix).
    (petk)

**SPL:**

  - Fixed bug php#73629
    (SplDoublyLinkedList::setIteratorMode masks intern
    flags). (J. Jeising, cmb)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-cdaaf6ea12"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"php-7.0.25-1.fc25")) flag++;


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
