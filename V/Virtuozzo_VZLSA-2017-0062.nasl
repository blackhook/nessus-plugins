#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101407);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2016-9131",
    "CVE-2016-9147",
    "CVE-2016-9444"
  );

  script_name(english:"Virtuozzo 7 : bind / bind-chroot / bind-devel / bind-libs / etc (VZLSA-2017-0062)");
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

* A denial of service flaw was found in the way BIND processed a
response to an ANY query. A remote attacker could use this flaw to
make named exit unexpectedly with an assertion failure via a specially
crafted DNS response. (CVE-2016-9131)

* A denial of service flaw was found in the way BIND handled a query
response containing inconsistent DNSSEC information. A remote attacker
could use this flaw to make named exit unexpectedly with an assertion
failure via a specially crafted DNS response. (CVE-2016-9147)

* A denial of service flaw was found in the way BIND handled an
unusually-formed DS record response. A remote attacker could use this
flaw to make named exit unexpectedly with an assertion failure via a
specially crafted DNS response. (CVE-2016-9444)

Red Hat would like to thank ISC for reporting these issues.

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-0062.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cbbdede");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017-0062");
  script_set_attribute(attribute:"solution", value:
"Update the affected bind / bind-chroot / bind-devel / bind-libs / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");

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
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");
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

pkgs = ["bind-9.9.4-38.vl7.1",
        "bind-chroot-9.9.4-38.vl7.1",
        "bind-devel-9.9.4-38.vl7.1",
        "bind-libs-9.9.4-38.vl7.1",
        "bind-libs-lite-9.9.4-38.vl7.1",
        "bind-license-9.9.4-38.vl7.1",
        "bind-lite-devel-9.9.4-38.vl7.1",
        "bind-pkcs11-9.9.4-38.vl7.1",
        "bind-pkcs11-devel-9.9.4-38.vl7.1",
        "bind-pkcs11-libs-9.9.4-38.vl7.1",
        "bind-pkcs11-utils-9.9.4-38.vl7.1",
        "bind-sdb-9.9.4-38.vl7.1",
        "bind-sdb-chroot-9.9.4-38.vl7.1",
        "bind-utils-9.9.4-38.vl7.1"];

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
