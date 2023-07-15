#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-96cb012029.
#

include("compat.inc");

if (description)
{
  script_id(135995);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");
  script_xref(name:"FEDORA", value:"2020-96cb012029");

  script_name(english:"Fedora 30 : php (2020-96cb012029)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**PHP version 7.3.17** (16 Apr 2020)

**Core:**

  - Fixed bug php#79364 (When copy empty array, next key is
    unspecified). (cmb)

  - Fixed bug php#78210 (Invalid pointer address). (cmb,
    Nikita)

**CURL:**

  - Fixed bug php#79199 (curl_copy_handle() memory leak).
    (cmb)

**Date:**

  - Fixed bug php#79396 (DateTime hour incorrect during DST
    jump forward). (Nate Brunette)

**Iconv:**

  - Fixed bug php#79200 (Some iconv functions cut
    Windows-1258). (cmb)

**OPcache:**

  - Fixed bug php#79412 (Opcache chokes and uses 100% CPU on
    specific script). (Dmitry)

**Session:**

  - Fixed bug php#79413 (session_create_id() fails for
    active sessions). (cmb)

**Shmop:**

  - Fixed bug php#79427 (Integer Overflow in shmop_open()).
    (cmb)

**SimpleXML:**

  - Fixed bug php#61597 (SXE properties may lack attributes
    and content). (cmb)

**Spl:**

  - Fixed bug php#75673 (SplStack::unserialize() behavior).
    (cmb)

  - Fixed bug php#79393 (Null coalescing operator failing
    with SplFixedArray). (cmb)

**Standard:**

  - Fixed bug php#79330 (shell_exec() silently truncates
    after a null byte). (stas)

  - Fixed bug php#79465 (OOB Read in urldecode()). (stas)

  - Fixed bug php#79410 (system() swallows last chunk if it
    is exactly 4095 bytes without newline). (Christian
    Schneider)

**Zip:**

  - Fixed Bug php#79296 (ZipArchive::open fails on empty
    file). (Remi)

  - Fixed bug php#79424 (php_zip_glob uses gl_pathc after
    call to globfree). (Max Rees)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-96cb012029"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"php-7.3.17-1.fc30")) flag++;


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
