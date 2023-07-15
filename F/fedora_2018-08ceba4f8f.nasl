#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-08ceba4f8f.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120222);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"FEDORA", value:"2018-08ceba4f8f");

  script_name(english:"Fedora 29 : php (2018-08ceba4f8f)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**PHP version 7.2.12** (08 Nov 2018)

**Core:**

  - Fixed bug php#76846 (Segfault in shutdown function after
    memory limit error). (Nikita)

  - Fixed bug php#76946 (Cyclic reference in generator not
    detected). (Nikita)

  - Fixed bug php#77035 (The phpize and ./configure create
    redundant .deps file). (Peter Kokot)

  - Fixed bug php#77041 (buildconf should output error
    messages to stderr) (Mizunashi Mana)

**Date:**

  - Upgraded timelib to 2017.08. (Derick)

  - Fixed bug php#75851 (Year component overflow with date
    formats 'c', 'o', 'r' and 'y'). (Adam Saponara)

  - Fixed bug php#77007 (fractions in `diff()` are not
    correctly normalized). (Derick)

**FCGI:**

  - Fixed php#76948 (Failed shutdown/reboot or end session
    in Windows). (Anatol)

  - Fixed bug php#76954 (apache_response_headers removes
    last character from header name). (stodorovic)

**FTP:**

  - Fixed bug php#76972 (Data truncation due to forceful ssl
    socket shutdown). (Manuel Mausz)

**intl:**

  - Fixed bug php#76942 (U_ARGUMENT_TYPE_MISMATCH). (anthrax
    at unixuser dot org)

**Reflection:**

  - Fixed bug php#76936 (Objects cannot access their private
    attributes while handling reflection errors). (Nikita)

  - Fixed bug php#66430 (ReflectionFunction::invoke does not
    invoke closure with object scope). (Nikita)

**Sodium:**

  - Some base64 outputs were truncated; this is not the case
    any more. (jedisct1)

  - block sizes >= 256 bytes are now supposed by
    sodium_pad() even when an old version of libsodium has
    been installed. (jedisct1)

  - Fixed bug php#77008 (sodium_pad() could read (but not
    return nor write) uninitialized memory when trying to
    pad an empty input). (jedisct1)

**Standard:**

  - Fixed bug php#76965 (INI_SCANNER_RAW doesn't strip
    trailing whitespace). (Pierrick)

**Tidy:**

  - Fixed bug php#77027 (tidy::getOptDoc() not available on
    Windows). (cmb)

**XML:**

  - Fixed bug php#30875 (xml_parse_into_struct() does not
    resolve entities). (cmb)

  - Add support for getting SKIP_TAGSTART and SKIP_WHITE
    options. (cmb)

**XMLRPC:**

  - Fixed bug php#75282 (xmlrpc_encode_request() crashes).
    (cmb)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-08ceba4f8f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/16");
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
if (! preg(pattern:"^29([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 29", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC29", reference:"php-7.2.12-1.fc29")) flag++;


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
