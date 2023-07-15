#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-f9d2203f3b.
#

include("compat.inc");

if (description)
{
  script_id(133379);
  script_version("1.4");
  script_cvs_date("Date: 2020/02/14");

  script_cve_id("CVE-2020-7059", "CVE-2020-7060");
  script_xref(name:"FEDORA", value:"2020-f9d2203f3b");

  script_name(english:"Fedora 30 : php (2020-f9d2203f3b)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**PHP version 7.3.14** (23 Jan 2020)

**Core**

  - Fixed bug php#78999 (Cycle leak when using function
    result as temporary). (Dmitry)

**CURL:**

  - Fixed bug php#79033 (Curl timeout error with specific
    url and post). (cmb)

**Date:**

  - Fixed bug php#79015 (undefined-behavior in php_date.c).
    (cmb)

**DBA:**

  - Fixed bug php#78808 ([LMDB] MDB_MAP_FULL: Environment
    mapsize limit reached). (cmb)

**Fileinfo:**

  - Fixed bug php#74170 (locale information change after
    mime_content_type). (Sergei Turchanov)

**GD:**

  - Fixed bug php#78923 (Artifacts when convoluting image
    with transparency). (wilson chen)

  - Fixed bug php#79067 (gdTransformAffineCopy() may use
    uninitialized values). (cmb)

  - Fixed bug php#79068 (gdTransformAffineCopy() changes
    interpolation method). (cmb)

**Libxml:**

  - Fixed bug php#79029 (Use After Free's in XMLReader /
    XMLWriter). (Laruence)

**Mbstring:**

  - Fixed bug php#79037 (global buffer-overflow in
    `mbfl_filt_conv_big5_wchar`). (CVE-2020-7060) (Nikita)

**OPcache:**

  - Fixed bug php#79040 (Warning Opcode handlers are
    unusable due to ASLR). (cmb)

**Pcntl:**

  - Fixed bug php#78402 (Converting null to string in error
    message is bad DX). (SAT&#x14C; Kentar&#x14D;)

**PDO_PgSQL:**

  - Fixed bug php#78983 (pdo_pgsql config.w32 cannot find
    libpq-fe.h). (SAT&#x14C; Kentar&#x14D;)

  - Fixed bug php#78980 (pgsqlGetNotify() overlooks dead
    connection). (SAT&#x14C; Kentar&#x14D;)

  - Fixed bug php#78982 (pdo_pgsql returns dead persistent
    connection). (SAT&#x14C; Kentar&#x14D;)

**Session:**

  - Fixed bug php#79091 (heap use-after-free in
    session_create_id()). (cmb, Nikita)

**Shmop:**

  - Fixed bug php#78538 (shmop memory leak). (cmb)

**Standard:**

  - Fixed bug php#79099 (OOB read in php_strip_tags_ex).
    (CVE-2020-7059). (cmb)

  - Fixed bug php#54298 (Using empty additional_headers
    adding extraneous CRLF). (cmb)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-f9d2203f3b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/31");
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
if (rpm_check(release:"FC30", reference:"php-7.3.14-1.fc30")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
