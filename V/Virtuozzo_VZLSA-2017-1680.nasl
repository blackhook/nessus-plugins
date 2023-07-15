#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104579);
  script_version("3.58");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2017-3142",
    "CVE-2017-3143"
  );

  script_name(english:"Virtuozzo 7 : bind / bind-chroot / bind-devel / bind-libs / etc (VZLSA-2017-1680)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for bind is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

Security Fix(es) :

* A flaw was found in the way BIND handled TSIG authentication for
dynamic updates. A remote attacker able to communicate with an
authoritative BIND server could use this flaw to manipulate the
contents of a zone, by forging a valid TSIG or SIG(0) signature for a
dynamic update request. (CVE-2017-3143)

* A flaw was found in the way BIND handled TSIG authentication of AXFR
requests. A remote attacker, able to communicate with an authoritative
BIND server, could use this flaw to view the entire contents of a zone
by sending a specially constructed request packet. (CVE-2017-3142)

Red Hat would like to thank Internet Systems Consortium for reporting
these issues. Upstream acknowledges Clement Berthaux (Synacktiv) as
the original reporter of these issues.

Bug Fix(es) :

* ICANN is planning to perform a Root Zone DNSSEC Key Signing Key
(KSK) rollover during October 2017. Maintaining an up-to-date KSK, by
adding the new root zone KSK, is essential for ensuring that
validating DNS resolvers continue to function following the rollover.
(BZ#1459649)

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-1680.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9f98cc9");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:1680");
  script_set_attribute(attribute:"solution", value:
"Update the affected bind / bind-chroot / bind-devel / bind-libs / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 7.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["bind-9.9.4-50.vl7.1",
        "bind-chroot-9.9.4-50.vl7.1",
        "bind-devel-9.9.4-50.vl7.1",
        "bind-libs-9.9.4-50.vl7.1",
        "bind-libs-lite-9.9.4-50.vl7.1",
        "bind-license-9.9.4-50.vl7.1",
        "bind-lite-devel-9.9.4-50.vl7.1",
        "bind-pkcs11-9.9.4-50.vl7.1",
        "bind-pkcs11-devel-9.9.4-50.vl7.1",
        "bind-pkcs11-libs-9.9.4-50.vl7.1",
        "bind-pkcs11-utils-9.9.4-50.vl7.1",
        "bind-sdb-9.9.4-50.vl7.1",
        "bind-sdb-chroot-9.9.4-50.vl7.1",
        "bind-utils-9.9.4-50.vl7.1"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-7", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-devel / bind-libs / etc");
}
