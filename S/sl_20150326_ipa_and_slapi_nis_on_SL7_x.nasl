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
  script_id(82293);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-0283", "CVE-2015-1827");

  script_name(english:"Scientific Linux Security Update : ipa and slapi-nis on SL7.x x86_64 (20150326)");
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
"The ipa component provides centrally managed Identity, Policy, and
Audit. The slapi-nis component provides NIS Server and Schema
Compatibility plug- ins for Directory Server.

It was discovered that the IPA extdom Directory Server plug-in did not
correctly perform memory reallocation when handling user account
information. A request for a list of groups for a user that belongs to
a large number of groups would cause a Directory Server to crash.
(CVE-2015-1827)

It was discovered that the slapi-nis Directory Server plug-in did not
correctly perform memory reallocation when handling user account
information. A request for information about a group with many
members, or a request for a user that belongs to a large number of
groups, would cause a Directory Server to enter an infinite loop and
consume an excessive amount of CPU time. (CVE-2015-0283)

This update fixes the following bugs :

  - Previously, users of IdM were not properly granted the
    default permission to read the
    'facsimiletelephonenumber' user attribute. This update
    adds 'facsimiletelephonenumber' to the Access Control
    Instruction (ACI) for user data, which makes the
    attribute readable to authenticated users as expected.

  - Prior to this update, when a DNS zone was saved in an
    LDAP database without a dot character (.) at the end,
    internal DNS commands and operations, such as
    dnsrecord-* or dnszone-*, failed. With this update, DNS
    commands always supply the DNS zone with a dot character
    at the end, which prevents the described problem.

  - After a full-server IdM restore operation, the restored
    server in some cases contained invalid data. In
    addition, if the restored server was used to
    reinitialize a replica, the replica then contained
    invalid data as well. To fix this problem, the IdM API
    is now created correctly during the restore operation,
    and *.ldif files are not skipped during the removal of
    RUV data. As a result, the restored server and its
    replica no longer contain invalid data.

  - Previously, a deadlock in some cases occurred during an
    IdM upgrade, which could cause the IdM server to become
    unresponsive. With this update, the Schema Compatibility
    plug-in has been adjusted not to parse the subtree that
    contains the configuration of the DNA plug-in, which
    prevents this deadlock from triggering.

  - When using the extdom plug-in of IdM to handle large
    groups, user lookups and group lookups previously failed
    due to insufficient buffer size. With this update, the
    getgrgid_r() call gradually increases the buffer length
    if needed, and the described failure of extdom thus no
    longer occurs."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1503&L=scientific-linux-errata&T=0&P=4007
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c0178c1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:slapi-nis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:slapi-nis-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-admintools-4.1.0-18.sl7_1.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-client-4.1.0-18.sl7_1.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-debuginfo-4.1.0-18.sl7_1.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-python-4.1.0-18.sl7_1.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-4.1.0-18.sl7_1.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.1.0-18.sl7_1.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"slapi-nis-0.54-3.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"slapi-nis-debuginfo-0.54-3.el7_1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-admintools / ipa-client / ipa-debuginfo / ipa-python / etc");
}
