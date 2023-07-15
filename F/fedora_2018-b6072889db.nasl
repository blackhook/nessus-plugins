#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-b6072889db.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120726);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-17082");
  script_xref(name:"FEDORA", value:"2018-b6072889db");

  script_name(english:"Fedora 28 : php (2018-b6072889db)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**PHP version 7.2.10** (13 Sep 2018)

**Core:**

  - Fixed bug php#76754 (parent private constant in extends
    class memory leak). (Laruence)

  - Fixed bug php#72443 (Generate enabled extension). (petk)

  - Fixed bug php#75797 (Memory leak when using
    class_alias() in non-debug mode). (Massimiliano Braglia)

**Apache2:**

  - Fixed bug php#76582 (Apache bucket brigade sometimes
    becomes invalid). (stas)

**Bz2:**

  - Fixed arginfo for bzcompress. (Tyson Andre)

**gettext:**

  - Fixed bug php#76517 (incorrect restoring of LDFLAGS).
    (sji)

**iconv:**

  - Fixed bug php#68180 (iconv_mime_decode can return extra
    characters in a header). (cmb)

  - Fixed bug php#63839 (iconv_mime_decode_headers function
    is skipping headers). (cmb)

  - Fixed bug php#60494 (iconv_mime_decode does ignore
    special characters). (cmb)

  - Fixed bug php#55146 (iconv_mime_decode_headers() skips
    some headers). (cmb)

**intl:**

  - Fixed bug php#74484 (MessageFormatter::formatMessage
    memory corruption with 11+ named placeholders). (Anatol)

**libxml:**

  - Fixed bug php#76777 ('public id' parameter of
    libxml_set_external_entity_loader callback undefined).
    (Ville Hukkam&auml;ki)

**mbstring:**

  - Fixed bug php#76704 (mb_detect_order return value varies
    based on argument type). (cmb)

**Opcache:**

  - Fixed bug php#76747 (Opcache treats path containing
    'test.pharma.tld' as a phar file). (Laruence)

**OpenSSL:**

  - Fixed bug php#76705 (unusable ssl => peer_fingerprint in
    stream_context_create()). (Jakub Zelenka)

**phpdbg:**

  - Fixed bug php#76595 (phpdbg man page contains outdated
    information). (Kevin Abel)

**SPL:**

  - Fixed bug php#68825 (Exception in
    DirectoryIterator::getLinkTarget()). (cmb)

  - Fixed bug php#68175 (RegexIterator pregFlags are NULL
    instead of 0). (Tim Siebels)

**Standard:**

  - Fixed bug php#76778 (array_reduce leaks memory if
    callback throws exception). (cmb)

**zlib:**

  - Fixed bug php#65988 (Zlib version check fails when an
    include/zlib/ style dir is passed to the --with-zlib
    configure option). (Jay Bonci)

  - Fixed bug php#76709 (Minimal required zlib library is
    1.2.0.4). (petk)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-b6072889db"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/22");
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
if (rpm_check(release:"FC28", reference:"php-7.2.10-1.fc28")) flag++;


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
