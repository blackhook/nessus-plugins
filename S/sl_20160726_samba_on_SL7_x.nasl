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
  script_id(92582);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-2119");

  script_name(english:"Scientific Linux Security Update : samba on SL7.x x86_64 (20160726)");
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

  - A flaw was found in the way Samba initiated signed
    DCE/RPC connections. A man-in-the-middle attacker could
    use this flaw to downgrade the connection to not use
    signing and therefore impersonate the server.
    (CVE-2016-2119)

Bug Fix(es) :

  - Previously, the 'net' command in some cases failed to
    join the client to Active Directory (AD) because the
    permissions setting prevented modification of the
    supported Kerberos encryption type LDAP attribute. With
    this update, Samba has been fixed to allow joining an AD
    domain as a user. In addition, Samba now uses the
    machine account credentials to set up the Kerberos
    encryption types within AD for the joined machine. As a
    result, using 'net' to join a domain now works more
    reliably.

  - Previously, the idmap_hash module worked incorrectly
    when it was used together with other modules. As a
    consequence, user and group IDs were not mapped
    properly. A patch has been applied to skip already
    configured modules. Now, the hash module can be used as
    the default idmap configuration back end and IDs are
    resolved correctly."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1607&L=scientific-linux-errata&F=&S=&P=12228
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5faa6f01"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-test-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-vfs-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/27");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsmbclient-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libsmbclient-devel-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwbclient-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwbclient-devel-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-client-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-client-libs-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", reference:"samba-common-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-common-libs-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-common-tools-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-dc-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-dc-libs-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-debuginfo-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-devel-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-libs-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", reference:"samba-pidl-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-python-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-test-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-test-devel-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-test-libs-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-vfs-glusterfs-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-winbind-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-winbind-clients-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-winbind-krb5-locator-4.2.10-7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"samba-winbind-modules-4.2.10-7.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsmbclient / libsmbclient-devel / libwbclient / libwbclient-devel / etc");
}
