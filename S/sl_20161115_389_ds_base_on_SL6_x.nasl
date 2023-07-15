#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(95049);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-4992", "CVE-2016-5405", "CVE-2016-5416");

  script_name(english:"Scientific Linux Security Update : 389-ds-base on SL6.x i386/x86_64 (20161115)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security Fix(es) :

  - It was found that 389 Directory Server was vulnerable to
    a flaw in which the default ACI (Access Control
    Instructions) could be read by an anonymous user. This
    could lead to leakage of sensitive information.
    (CVE-2016-5416)

  - An information disclosure flaw was found in 389
    Directory Server. A user with no access to objects in
    certain LDAP sub-tree could send LDAP ADD operations
    with a specific object name. The error message returned
    to the user was different based on whether the target
    object existed or not. (CVE-2016-4992)

  - It was found that 389 Directory Server was vulnerable to
    a remote password disclosure via timing attack. A remote
    attacker could possibly use this flaw to retrieve
    directory server password after many tries.
    (CVE-2016-5405)

Bug Fix(es) :

  - Previously, a bug in the changelog iterator buffer
    caused it to point to an incorrect position when
    reloading the buffer. This caused replication to skip
    parts of the changelog, and consequently some changes
    were not replicated. This bug has been fixed, and
    replication data loss due to an incorrectly reloaded
    changelog buffer no longer occurs.

  - Previously, if internal modifications were generated on
    a consumer (for example by the Account Policy plug-in)
    and additional changes to the same attributes were
    received from replication, a bug caused Directory Server
    to accumulate state information on the consumer. The bug
    has been fixed by making sure that replace operations
    are only applied if they are newer than existing
    attribute deletion change sequence numbers (CSNs), and
    state information no longer accumulates in this
    situation.

Enhancement(s) :

  - In a multi-master replication environment where multiple
    masters receive updates at the same time, it was
    previously possible for a single master to obtain
    exclusive access to a replica and hold it for a very
    long time due to problems such as a slow network
    connection. During this time, other masters were blocked
    from accessing the same replica, which considerably
    slowed down the replication process. This update adds a
    new configuration attribute,
    'nsds5ReplicaReleaseTimeout', which can be used to
    specify a timeout in seconds. After the specified
    timeout period passes, the master releases the replica,
    allowing other masters to access it and send their
    updates."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1611&L=scientific-linux-errata&F=&S=&P=4058
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?041e0472"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"389-ds-base-1.2.11.15-84.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"389-ds-base-debuginfo-1.2.11.15-84.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"389-ds-base-devel-1.2.11.15-84.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"389-ds-base-libs-1.2.11.15-84.el6_8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-debuginfo / 389-ds-base-devel / etc");
}
