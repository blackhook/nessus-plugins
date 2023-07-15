#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-06c24068c6.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111469);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"FEDORA", value:"2018-06c24068c6");

  script_name(english:"Fedora 27 : python-cryptography / python-cryptography-vectors (2018-06c24068c6)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"# New upstream release 2.3

Fixes possible tag truncation security bug in AEAD API, see
RHBZ#1602752

## 2.3 - 2018-07-18

  - SECURITY ISSUE: finalize_with_tag() allowed tag
    truncation by default which can allow tag forgery in
    some cases. The method now enforces the min_tag_length
    provided to the GCM constructor.

  - Added support for Python 3.7.

  - Added extract_timestamp() to get the authenticated
    timestamp of a Fernet token.

  - Support for Python 2.7.x without hmac.compare_digest has
    been deprecated. We will require Python 2.7.7 or higher
    (or 2.7.6 on Ubuntu) in the next cryptography release.

  - Fixed multiple issues preventing cryptography from
    compiling against LibreSSL 2.7.x.

  - Added get_revoked_certificate_by_serial_number for quick
    serial number searches in CRLs.

  - The RelativeDistinguishedName class now preserves the
    order of attributes. Duplicate attributes now raise an
    error instead of silently discarding duplicates.

  - aes_key_unwrap() and aes_key_unwrap_with_padding() now
    raise InvalidUnwrap if the wrapped key is an invalid
    length, instead of ValueError.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-06c24068c6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected python-cryptography and / or
python-cryptography-vectors packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python-cryptography-vectors");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:27");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^27([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 27", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC27", reference:"python-cryptography-2.3-1.fc27")) flag++;
if (rpm_check(release:"FC27", reference:"python-cryptography-vectors-2.3-1.fc27")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-cryptography / python-cryptography-vectors");
}
