#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-523f6a613d.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105878);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-14737");
  script_xref(name:"FEDORA", value:"2017-523f6a613d");

  script_name(english:"Fedora 27 : botan (2017-523f6a613d)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"#### Version 1.10.17, 2017-10-02 ####

  - Address a side channel affecting modular exponentiation.
    An attacker capable of a local or cross-VM cache
    analysis attack may be able to recover bits of secret
    exponents as used in RSA, DH, etc. (CVE-2017-14737)

  - Workaround a miscompilation bug in GCC 7 on x86-32
    affecting GOST-34.11 hash function. [GH
    #1192](https://github.com/randombit/botan/issues/1192)
    [GH
    #1148](https://github.com/randombit/botan/issues/1148)
    [GH #882](https://github.com/randombit/botan/issues/882)

  - Add SecureVector::data() function which returns the
    start of the buffer. This makes it slightly simpler to
    support both 1.10 and 2.x APIs in the same codebase.

  - When compiled by a C++11 (or later) compiler, a template
    typedef of SecureVector, secure_vector, is added. In 2.x
    this class is a std::vector with a custom allocator, so
    has a somewhat different interface than SecureVector in
    1.10. But this makes it slightly simpler to support both
    1.10 and 2.x APIs in the same codebase.

  - Fix a bug that prevented `configure.py` from running
    under Python3

  - Botan 1.10.x does not support the OpenSSL 1.1 API. Now
    the build will #error if OpenSSL 1.1 is detected. Avoid
    &ndash;with-openssl if compiling against 1.1 or later.
    [GH #753](https://github.com/randombit/botan/issues/753)

  - Import patches from Debian adding basic support for
    building on aarch64, ppc64le, or1k, and mipsn32
    platforms.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-523f6a613d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/randombit/botan/issues/1148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/randombit/botan/issues/1192"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected botan package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:botan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:27");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/15");
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
if (rpm_check(release:"FC27", reference:"botan-1.10.17-1.fc27")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "botan");
}
