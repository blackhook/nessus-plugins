#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-b674dc22ad.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101538);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-9224", "CVE-2017-9226", "CVE-2017-9227", "CVE-2017-9228", "CVE-2017-9229");
  script_xref(name:"FEDORA", value:"2017-b674dc22ad");

  script_name(english:"Fedora 25 : php (2017-b674dc22ad)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**PHP version 7.0.21** (06 Jul 2017)

**Core:**

  - Fixed bug php#74738 (Multiple [PATH=] and [HOST=]
    sections not properly parsed). (Manuel Mausz)

  - Fixed bug php#74658 (Undefined constants in array
    properties result in broken properties). (Laruence)

  - Fixed misparsing of abstract unix domain socket names.
    (Sara)

  - Fixed bug php#74101, bug php#74614 (Unserialize Heap
    Use-After-Free (READ: 1) in zval_get_type). (Nikita)

  - Fixed bug php#74111 (Heap buffer overread (READ: 1)
    finish_nested_data from unserialize). (Nikita)

  - Fixed bug php#74603 (PHP INI Parsing Stack Buffer
    Overflow Vulnerability). (Stas)

  - Fixed bug php#74819 (wddx_deserialize() heap
    out-of-bound read via php_parse_date()). (Derick)

**DOM:**

  - Fixed bug php#69373 (References to deleted XPath query
    results). (ttoohey)

**Intl:**

  - Fixed bug php#73473 (Stack Buffer Overflow in
    msgfmt_parse_message). (libnex)

  - Fixed bug php#74705 (Wrong reflection on
    Collator::getSortKey and collator_get_sort_key). (Tyson
    Andre, Remi)

  - Fixed bug php#73634 (grapheme_strpos illegal memory
    access). (Stas)

**Mbstring:**

  - Add oniguruma upstream fix (CVE-2017-9224,
    CVE-2017-9226, CVE-2017-9227, CVE-2017-9228,
    CVE-2017-9229) (Remi, Mamoru TASAKA)

**Opcache:**

  - Fixed bug php#74663 (Segfault with
    opcache.memory_protect and validate_timestamp).
    (Laruence)

**OpenSSL:**

  - Fixed bug php#74651 (negative-size-param (-1) in memcpy
    in zif_openssl_seal()). (Stas)

**Reflection:**

  - Fixed bug php#74673 (Segfault when cast Reflection
    object to string with undefined constant). (Laruence)

**SPL:**

  - Fixed bug php#74478 (null coalescing operator failing
    with SplFixedArray). (jhdxr)

**Standard:**

  - Fixed bug php#74708 (Invalid Reflection signatures for
    random_bytes and random_int). (Tyson Andre, Remi)

  - Fixed bug php#73648 (Heap buffer overflow in substr).
    (Stas)

**FTP:**

  - Fixed bug php#74598 (ftp:// wrapper ignores context
    arg). (Sara)

**PHAR:**

  - Fixed bug php#74386 (Phar::__construct reflection
    incorrect). (villfa)

**SOAP**

  - Fixed bug php#74679 (Incorrect conversion array with
    WSDL_CACHE_MEMORY). (Dmitry)

**Streams:**

  - Fixed bug php#74556 (stream_socket_get_name() returns
    '\0'). (Sara)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-b674dc22ad"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/14");
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
if (rpm_check(release:"FC25", reference:"php-7.0.21-1.fc25")) flag++;


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
