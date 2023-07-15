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
  script_id(102972);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-7551");

  script_name(english:"Scientific Linux Security Update : 389-ds-base on SL7.x x86_64 (20170905)");
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

  - A flaw was found in the way 389-ds-base handled
    authentication attempts against locked accounts. A
    remote attacker could potentially use this flaw to
    continue password brute-forcing attacks against LDAP
    accounts, thereby bypassing the protection offered by
    the directory server's password lockout policy.
    (CVE-2017-7551)

Bug Fix(es) :

  - In a multi-replication environments, if operations in
    one back end triggered updates in another back end, the
    Replica Update Vector (RUV) of the back end was
    incorrect and replication failed. This fix enables
    Directory Server to handle Change Sequence Number (CSN)
    pending lists across multiple back ends. As a result,
    replication works correctly.

  - Due to a low default entry cache size value, the
    Directory Server database had to resolve many deadlocks
    during resource-intensive tasks. In certain situations,
    this could result in a 'DB PANIC' error and the server
    no longer responded to requests. After the server was
    restarted, Directory Server started with a delay to
    recover the database. However, this recovery could fail,
    and the database could corrupt. This patch increases the
    default entry cache size in the nsslapd-cachememsize
    parameter to 200 MB. As a result, out-of-lock situations
    or 'DB PANIC' errors no longer occur in the mentioned
    scenario.

  - Previously, if replication was enabled and a changelog
    file existed, performing a backup on this master server
    failed. This update sets the internal options for
    correctly copying a file. As a result, creating a backup
    now succeeds in the mentioned scenario.

  - In certain situations, if the server was previously
    abruptly shut down, the
    /etc/dirsrv/<instance_name>/dse.ldif configuration file
    became corrupted. As a consequence, Directory Server
    failed to start. With this patch, the server now calls
    the fsync() function before shutting down to force the
    file system to write any changes to the disk. As a
    result, the configuration no longer becomes corrupted,
    regardless how the server gets stopped."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1709&L=scientific-linux-errata&F=&S=&P=80
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a07f6bf8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-snmp");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-1.3.6.1-19.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-debuginfo-1.3.6.1-19.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-devel-1.3.6.1-19.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-libs-1.3.6.1-19.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-snmp-1.3.6.1-19.el7_4")) flag++;


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
