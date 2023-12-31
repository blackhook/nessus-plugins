#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0902. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59596);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-1586");
  script_bugtraq_id(52742, 53246);
  script_xref(name:"RHSA", value:"2012:0902");

  script_name(english:"RHEL 6 : cifs-utils (RHSA-2012:0902)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated cifs-utils package that fixes one security issue, multiple
bugs, and adds various enhancements is now available for Red Hat
Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The cifs-utils package contains tools for mounting and managing shares
on Linux using the SMB/CIFS protocol. The CIFS shares can be used as
standard Linux file systems.

A file existence disclosure flaw was found in mount.cifs. If the tool
was installed with the setuid bit set, a local attacker could use this
flaw to determine the existence of files or directories in directories
not accessible to the attacker. (CVE-2012-1586)

Note: mount.cifs from the cifs-utils package distributed by Red Hat
does not have the setuid bit set. We recommend that administrators do
not manually set the setuid bit for mount.cifs.

This update also fixes the following bugs :

* The cifs.mount(8) manual page was previously missing documentation
for several mount options. With this update, the missing entries have
been added to the manual page. (BZ#769923)

* Previously, the mount.cifs utility did not properly update the
'/etc/mtab' system information file when remounting an existing CIFS
mount. Consequently, mount.cifs created a duplicate entry of the
existing mount entry. This update adds the del_mtab() function to
cifs.mount, which ensures that the old mount entry is removed from
'/etc/mtab' before adding the updated mount entry. (BZ#770004)

* The mount.cifs utility did not properly convert user and group names
to numeric UIDs and GIDs. Therefore, when the 'uid', 'gid' or 'cruid'
mount options were specified with user or group names, CIFS shares
were mounted with default values. This caused shares to be
inaccessible to the intended users because UID and GID is set to '0'
by default. With this update, user and group names are properly
converted so that CIFS shares are now mounted with specified user and
group ownership as expected. (BZ#796463)

* The cifs.upcall utility did not respect the 'domain_realm' section
in the 'krb5.conf' file and worked only with the default domain.
Consequently, an attempt to mount a CIFS share from a different than
the default domain failed with the following error message :

mount error(126): Required key not available

This update modifies the underlying code so that cifs.upcall handles
multiple Kerberos domains correctly and CIFS shares can now be mounted
as expected in a multi-domain environment. (BZ#805490)

In addition, this update adds the following enhancements :

* The cifs.upcall utility previously always used the '/etc/krb5.conf'
file regardless of whether the user had specified a custom Kerberos
configuration file. This update adds the '--krb5conf' option to
cifs.upcall allowing the administrator to specify an alternate
krb5.conf file. For more information on this option, refer to the
cifs.upcall(8) manual page. (BZ#748756)

* The cifs.upcall utility did not optimally determine the correct
service principal name (SPN) used for Kerberos authentication, which
occasionally caused krb5 authentication to fail when mounting a
server's unqualified domain name. This update improves cifs.upcall so
that the method used to determine the SPN is now more versatile.
(BZ#748757)

* This update adds the 'backupuid' and 'backupgid' mount options to
the mount.cifs utility. When specified, these options grant a user or
a group the right to access files with the backup intent. For more
information on these options, refer to the mount.cifs(8) manual page.
(BZ#806337)

All users of cifs-utils are advised to upgrade to this updated
package, which contains backported patches to fix these issues and add
these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2012:0902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-1586"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cifs-utils and / or cifs-utils-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cifs-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cifs-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0902";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"cifs-utils-4.8.1-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"cifs-utils-4.8.1-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"cifs-utils-4.8.1-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"cifs-utils-debuginfo-4.8.1-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"cifs-utils-debuginfo-4.8.1-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"cifs-utils-debuginfo-4.8.1-10.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cifs-utils / cifs-utils-debuginfo");
  }
}
