#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0619. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90496);
  script_version("2.19");
  script_cvs_date("Date: 2019/10/24 15:35:41");

  script_cve_id("CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2115", "CVE-2016-2118");
  script_xref(name:"RHSA", value:"2016:0619");

  script_name(english:"RHEL 6 : samba (RHSA-2016:0619) (Badlock)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for samba is now available for Red Hat Enterprise Linux 6.2
Advanced Update Support, Red Hat Enterprise Linux 6.4 Advanced Update
Support, Red Hat Enterprise Linux 6.5 Advanced Update Support, and Red
Hat Enterprise Linux 6.6 Extended Update Support.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) protocol and the related Common Internet File System (CIFS)
protocol, which allow PC-compatible machines to share files, printers,
and various information.

Security Fix(es) :

* Multiple flaws were found in Samba's DCE/RPC protocol
implementation. A remote, authenticated attacker could use these flaws
to cause a denial of service against the Samba server (high CPU load
or a crash) or, possibly, execute arbitrary code with the permissions
of the user running Samba (root). This flaw could also be used to
downgrade a secure DCE/RPC connection by a man-in-the-middle attacker
taking control of an Active Directory (AD) object and compromising the
security of a Samba Active Directory Domain Controller (DC).
(CVE-2015-5370)

Note: While Samba packages as shipped in Red Hat Enterprise Linux do
not support running Samba as an AD DC, this flaw applies to all roles
Samba implements.

* A protocol flaw, publicly referred to as Badlock, was found in the
Security Account Manager Remote Protocol (MS-SAMR) and the Local
Security Authority (Domain Policy) Remote Protocol (MS-LSAD). Any
authenticated DCE/RPC connection that a client initiates against a
server could be used by a man-in-the-middle attacker to impersonate
the authenticated user against the SAMR or LSA service on the server.
As a result, the attacker would be able to get read/write access to
the Security Account Manager database, and use this to reveal all
passwords or any other potentially sensitive information in that
database. (CVE-2016-2118)

* Several flaws were found in Samba's implementation of NTLMSSP
authentication. An unauthenticated, man-in-the-middle attacker could
use this flaw to clear the encryption and integrity flags of a
connection, causing data to be transmitted in plain text. The attacker
could also force the client or server into sending data in plain text
even if encryption was explicitly requested for that connection.
(CVE-2016-2110)

* It was discovered that Samba configured as a Domain Controller would
establish a secure communication channel with a machine using a
spoofed computer name. A remote attacker able to observe network
traffic could use this flaw to obtain session-related information
about the spoofed machine. (CVE-2016-2111)

* It was found that Samba's LDAP implementation did not enforce
integrity protection for LDAP connections. A man-in-the-middle
attacker could use this flaw to downgrade LDAP connections to use no
integrity protection, allowing them to hijack such connections.
(CVE-2016-2112)

* It was found that Samba did not enable integrity protection for IPC
traffic by default. A man-in-the-middle attacker could use this flaw
to view and modify the data sent between a Samba server and a client.
(CVE-2016-2115)

Red Hat would like to thank the Samba project for reporting these
issues. Upstream acknowledges Jouni Knuutinen (Synopsis) as the
original reporter of CVE-2015-5370; and Stefan Metzmacher (SerNet) as
the original reporter of CVE-2016-2118, CVE-2016-2110, CVE-2016-2112,
and CVE-2016-2115."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/vulnerabilities/badlock"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/2253041"
  );
  # http://badlock.org/
  script_set_attribute(
    attribute:"see_also",
    value:"https://samba.plus"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/2243351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:0619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-5370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-2115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-2112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-2118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-2111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-2110"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(6\.2|6\.4|6\.5|6\.6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.2 / 6.4 / 6.5 / 6.6", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:0619";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
{  sp = get_kb_item("Host/RedHat/minor_release");
  if (isnull(sp)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");

  flag = 0;
  if (rpm_check(release:"RHEL6", sp:"6", reference:"libsmbclient-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"libsmbclient-3.6.23-30.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"libsmbclient-3.6.23-30.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"libsmbclient-3.6.23-30.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"libsmbclient-3.6.23-30.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"libsmbclient-3.6.23-30.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"libsmbclient-3.6.23-30.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", reference:"libsmbclient-devel-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"libsmbclient-devel-3.6.23-30.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"libsmbclient-devel-3.6.23-30.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"libsmbclient-devel-3.6.23-30.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"libsmbclient-devel-3.6.23-30.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"libsmbclient-devel-3.6.23-30.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"libsmbclient-devel-3.6.23-30.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"samba-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"samba-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"samba-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"samba-3.6.23-30.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"samba-3.6.23-30.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"samba-3.6.23-30.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"samba-client-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"samba-client-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"samba-client-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"samba-client-3.6.23-30.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"samba-client-3.6.23-30.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"samba-client-3.6.23-30.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", reference:"samba-common-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"samba-common-3.6.23-30.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"samba-common-3.6.23-30.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"samba-common-3.6.23-30.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"samba-common-3.6.23-30.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"samba-common-3.6.23-30.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"samba-common-3.6.23-30.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", reference:"samba-debuginfo-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"samba-debuginfo-3.6.23-30.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"samba-debuginfo-3.6.23-30.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"samba-debuginfo-3.6.23-30.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"samba-debuginfo-3.6.23-30.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"samba-debuginfo-3.6.23-30.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"samba-debuginfo-3.6.23-30.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"samba-doc-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"samba-doc-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"samba-doc-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"samba-doc-3.6.23-30.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"samba-doc-3.6.23-30.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"samba-doc-3.6.23-30.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"samba-domainjoin-gui-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"samba-domainjoin-gui-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"samba-domainjoin-gui-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"samba-domainjoin-gui-3.6.23-30.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"samba-domainjoin-gui-3.6.23-30.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"samba-domainjoin-gui-3.6.23-30.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"samba-glusterfs-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"samba-swat-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"samba-swat-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"samba-swat-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"samba-swat-3.6.23-30.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"samba-swat-3.6.23-30.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"samba-swat-3.6.23-30.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"samba-winbind-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"samba-winbind-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"samba-winbind-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"samba-winbind-3.6.23-30.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"samba-winbind-3.6.23-30.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"samba-winbind-3.6.23-30.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", reference:"samba-winbind-clients-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"samba-winbind-clients-3.6.23-30.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"samba-winbind-clients-3.6.23-30.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"samba-winbind-clients-3.6.23-30.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"samba-winbind-clients-3.6.23-30.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"samba-winbind-clients-3.6.23-30.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"samba-winbind-clients-3.6.23-30.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", reference:"samba-winbind-devel-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"samba-winbind-devel-3.6.23-30.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"samba-winbind-devel-3.6.23-30.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"samba-winbind-devel-3.6.23-30.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"samba-winbind-devel-3.6.23-30.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"samba-winbind-devel-3.6.23-30.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"samba-winbind-devel-3.6.23-30.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"samba-winbind-krb5-locator-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"samba-winbind-krb5-locator-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"samba-winbind-krb5-locator-3.6.23-30.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"samba-winbind-krb5-locator-3.6.23-30.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"samba-winbind-krb5-locator-3.6.23-30.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"samba-winbind-krb5-locator-3.6.23-30.el6_5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsmbclient / libsmbclient-devel / samba / samba-client / etc");
  }
}
