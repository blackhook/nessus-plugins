#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1138. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(39597);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-2185", "CVE-2009-2661");
  script_bugtraq_id(35452);
  script_xref(name:"RHSA", value:"2009:1138");

  script_name(english:"RHEL 5 : openswan (RHSA-2009:1138)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openswan packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Openswan is a free implementation of Internet Protocol Security
(IPsec) and Internet Key Exchange (IKE). IPsec uses strong
cryptography to provide both authentication and encryption services.
These services allow you to build secure tunnels through untrusted
networks. Everything passing through the untrusted network is
encrypted by the IPsec gateway machine, and decrypted by the gateway
at the other end of the tunnel. The resulting tunnel is a virtual
private network (VPN).

Multiple insufficient input validation flaws were found in the way
Openswan's pluto IKE daemon processed some fields of X.509
certificates. A remote attacker could provide a specially crafted
X.509 certificate that would crash the pluto daemon. (CVE-2009-2185)

All users of openswan are advised to upgrade to these updated
packages, which contain a backported patch to correct these issues.
After installing this update, the ipsec service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-2185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2009:1138"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openswan and / or openswan-doc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openswan-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:1138";
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
{
  flag = 0;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openswan-2.6.14-1.el5_3.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openswan-2.6.14-1.el5_3.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openswan-2.6.14-1.el5_3.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openswan-doc-2.6.14-1.el5_3.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openswan-doc-2.6.14-1.el5_3.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openswan-doc-2.6.14-1.el5_3.3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openswan / openswan-doc");
  }
}
