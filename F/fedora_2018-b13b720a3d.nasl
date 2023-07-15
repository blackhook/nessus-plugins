#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-b13b720a3d.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120716);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"FEDORA", value:"2018-b13b720a3d");

  script_name(english:"Fedora 28 : php (2018-b13b720a3d)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**PHP version 7.2.4** (29 Mar 2018)

**Core:**

  - Fixed bug php#76025 (Segfault while throwing exception
    in error_handler). (Dmitry, Laruence)

  - Fixed bug php#76044 ('date: illegal option -- -' in
    ./configure on FreeBSD). (Anatol)

**FPM:**

  - Fixed bug php#75605 (Dumpable FPM child processes allow
    bypassing opcache access controls). (Jakub Zelenka)

**FTP:**

  - Fixed ftp_pasv arginfo. (carusogabriel)

**GD:**

  - Fixed bug php#73957 (signed integer conversion in
    imagescale()). (cmb)

  - Fixed bug php#76041 (NULL pointer access crashed php).
    (cmb)

  - Fixed imagesetinterpolation arginfo. (Gabriel Caruso)

**iconv:**

  - Fixed bug php#75867 (Freeing uninitialized pointer).
    (Philip Prindeville)

**Mbstring:**

  - Fixed bug php#62545 (wrong unicode mapping in some
    charsets). (cmb)

**Opcache:**

  - Fixed bug php#75969 (Assertion failure in live range DCE
    due to block pass misoptimization). (Nikita)

**OpenSSL:**

  - Fixed openssl_* arginfos. (carusogabriel)

**PCNTL:**

  - Fixed bug php#75873 (pcntl_wexitstatus returns incorrect
    on Big_Endian platform (s390x)). (Sam Ding)

**Phar:**

  - Fixed bug php#76085 (Segmentation fault in
    buildFromIterator when directory name contains a ).
    (Laruence)

**Standard:**

  - Fixed bug php#75961 (Strange references behavior).
    (Laruence)

  - Fixed some arginfos. (carusogabriel)

  - Fixed bug php#76068 (parse_ini_string fails to parse
    '[foo] bar=1|>baz' with segfault). (Anatol)

----

**Packaging changes:**

  - add file trigger to restart the php-fpm service when new
    pool or new extension installed 

  - use systemd RuntimeDirectory instead of /etc/tmpfiles.d

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-b13b720a3d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^28([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 28", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC28", reference:"php-7.2.4-1.fc28")) flag++;


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
