#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101534);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2017-9148"
  );

  script_name(english:"Virtuozzo 7 : freeradius / freeradius-devel / freeradius-doc / etc (VZLSA-2017-1581)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for freeradius is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

FreeRADIUS is a high-performance and highly configurable free Remote
Authentication Dial In User Service (RADIUS) server, designed to allow
centralized authentication and authorization for a network.

Security Fix(es) :

* An authentication bypass flaw was found in the way the EAP module in
FreeRADIUS handled TLS session resumption. A remote unauthenticated
attacker could potentially use this flaw to bypass the inner
authentication check in FreeRADIUS by resuming an older
unauthenticated TLS session. (CVE-2017-9148)

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-1581.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67848d31");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017-1581");
  script_set_attribute(attribute:"solution", value:
"Update the affected freeradius / freeradius-devel / freeradius-doc / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/14");
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

pkgs = ["freeradius-3.0.4-8.vl7",
        "freeradius-devel-3.0.4-8.vl7",
        "freeradius-doc-3.0.4-8.vl7",
        "freeradius-krb5-3.0.4-8.vl7",
        "freeradius-ldap-3.0.4-8.vl7",
        "freeradius-mysql-3.0.4-8.vl7",
        "freeradius-perl-3.0.4-8.vl7",
        "freeradius-postgresql-3.0.4-8.vl7",
        "freeradius-python-3.0.4-8.vl7",
        "freeradius-sqlite-3.0.4-8.vl7",
        "freeradius-unixODBC-3.0.4-8.vl7",
        "freeradius-utils-3.0.4-8.vl7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-7", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius / freeradius-devel / freeradius-doc / etc");
}
