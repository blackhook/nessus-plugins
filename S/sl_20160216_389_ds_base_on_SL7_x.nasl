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
  script_id(88795);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-0741");

  script_name(english:"Scientific Linux Security Update : 389-ds-base on SL7.x x86_64 (20160216)");
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
"An infinite-loop vulnerability was discovered in the 389 directory
server, where the server failed to correctly handle unexpectedly
closed client connections. A remote attacker able to connect to the
server could use this flaw to make the directory server consume an
excessive amount of CPU and stop accepting connections (denial of
service). (CVE-2016-0741)

This update fixes the following bugs :

  - Previously, if a simple paged results search failed in
    the back end, the simple paged results slot was not
    released. Consequently, the simple paged results slots
    in a connection object could be accumulated. With this
    update, the simple paged results slot is released
    correctly when a search fails, and unused simple paged
    results slots are no longer left in a connection object.

  - Previously, when several values of the same attribute
    were deleted using the ldapmodify command, and at least
    one of them was added again during the same operation,
    the equality index was not updated. As a consequence, an
    exact search for the re-added attribute value did not
    return the entry. The logic of the index code has been
    modified to update the index if at least one of the
    values in the entry changes, and the exact search for
    the re-added attribute value now returns the correct
    entry.

  - Prior to this update, when the cleanAllRUV task was
    running, a bogus attrlist_replace error message was
    logged repeatedly due to a memory corruption. With this
    update, the appropriate memory copy function memmove is
    used, which fixes the memory corruption. As a result,
    the error messages are no longer logged in this
    scenario.

  - To fix a simple paged results bug, an exclusive lock on
    a connection was previously added. This consequently
    caused a self deadlock in a particular case. With this
    update, the exclusive lock on a connection has been
    changed to the re-entrant type, and the self deadlock no
    longer occurs.

  - Previously, an unnecessary lock was sometimes acquired
    on a connection object, which could consequently cause a
    deadlock. A patch has been applied to remove the
    unnecessary locking, and the deadlock no longer occurs.

After installing this update, the 389 server service will be restarted
automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1602&L=scientific-linux-errata&F=&S=&P=9778
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18665270"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/17");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-1.3.4.0-26.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-debuginfo-1.3.4.0-26.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-devel-1.3.4.0-26.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-libs-1.3.4.0-26.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-debuginfo / 389-ds-base-devel / etc");
}
