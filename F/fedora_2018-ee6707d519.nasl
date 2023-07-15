#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-ee6707d519.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120886);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-10546", "CVE-2018-10547", "CVE-2018-10548", "CVE-2018-10549", "CVE-2018-5712");
  script_xref(name:"FEDORA", value:"2018-ee6707d519");

  script_name(english:"Fedora 28 : php (2018-ee6707d519)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**PHP version 7.2.5** (26 Apr 2018)

**Core:**

  - Fixed bug php#75722 (Convert valgrind detection to
    configure option). (Michael Heimpold)

**Date:**

  - Fixed bug php#76131 (mismatch arginfo for date_create).
    (carusogabriel)

**Exif:**

  - Fixed bug php#76130 (Heap Buffer Overflow (READ: 1786)
    in exif_iif_add_value). (Stas)

**FPM:**

  - Fixed bug php#68440 (ERROR: failed to reload: execvp()
    failed: Argument list too long). (Jacob Hipps)

  - Fixed incorrect write to getenv result in FPM reload.
    (Jakub Zelenka)

**GD:**

  - Fixed bug php#52070 (imagedashedline() - dashed line
    sometimes is not visible). (cmb)

**intl:**

  - Fixed bug php#76153 (Intl compilation fails with icu4c
    61.1). (Anatol)

**iconv:**

  - Fixed bug php#76249 (stream filter convert.iconv leads
    to infinite loop on invalid sequence). (Stas)

**ldap:**

  - Fixed bug php#76248 (Malicious LDAP-Server Response
    causes Crash). (Stas)

**mbstring:**

  - Fixed bug php#75944 (Wrong cp1251 detection). (dmk001)

  - Fixed bug php#76113 (mbstring does not build with
    Oniguruma 6.8.1). (chrullrich, cmb)

**ODBC:**

  - Fixed bug php#76088 (ODBC functions are not available by
    default on Windows). (cmb)

**Opcache:**

  - Fixed bug php#76094 (Access violation when using
    opcache). (Laruence)

**Phar:**

  - Fixed bug php#76129 (fix for CVE-2018-5712 may not be
    complete). (Stas)

**phpdbg:**

  - Fixed bug php#76143 (Memory corruption: arbitrary NUL
    overwrite). (Laruence)

**SPL:**

  - Fixed bug php#76131 (mismatch arginfo for splarray
    constructor). (carusogabriel)

**standard:**

  - Fixed bug php#74139 (mail.add_x_header default
    inconsistent with docs). (cmb)

  - Fixed bug php#75996 (incorrect url in header for
    mt_rand). (tatarbj)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-ee6707d519"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/03");
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
if (rpm_check(release:"FC28", reference:"php-7.2.5-1.fc28")) flag++;


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
