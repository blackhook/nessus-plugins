#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-aa6036fcb3.
#

include("compat.inc");

if (description)
{
  script_id(121264);
  script_version("1.2");
  script_cvs_date("Date: 2019/09/23 11:21:11");

  script_xref(name:"FEDORA", value:"2019-aa6036fcb3");

  script_name(english:"Fedora 29 : php (2019-aa6036fcb3)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**PHP version 7.2.14** (10 Jan 2019)

**Core:**

  - Fixed bug php#77369 (memcpy with negative length via
    crafted DNS response). (Stas)

  - Fixed bug php#71041 (zend_signal_startup() needs
    ZEND_API). (Valentin V. Bartenev)

  - Fixed bug php#76046 (PHP generates 'FE_FREE' opcode on
    the wrong line). (Nikita)

**Date:**

  - Fixed bug php#77097 (DateTime::diff gives wrong diff
    when the actual diff is less than 1 second). (Derick)

**Exif:**

  - Fixed bug php#77184 (Unsigned rational numbers are
    written out as signed rationals). (Colin Basnett)

**Opcache:**

  - Fixed bug php#77215 (CFG assertion failure on multiple
    finalizing switch frees in one block). (Nikita)

**PDO:**

  - Handle invalid index passed to
    PDOStatement::fetchColumn() as error. (Sergei Morozov)

**Phar:**

  - Fixed bug php#77247 (heap buffer overflow in
    phar_detect_phar_fname_ext). (Stas)

**Sockets:**

  - Fixed bug php#77136 (Unsupported IPV6_RECVPKTINFO
    constants on macOS). (Mizunashi Mana)

**SQLite3:**

  - Fixed bug php#77051 (Issue with re-binding on SQLite3).
    (BohwaZ)

**Xmlrpc:**

  - Fixed bug php#77242 (heap out of bounds read in
    xmlrpc_decode()). (cmb)

  - Fixed bug php#77380 (Global out of bounds read in xmlrpc
    base64 code). (Stas)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-aa6036fcb3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/22");
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
if (rpm_check(release:"FC29", reference:"php-7.2.14-1.fc29")) flag++;


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
