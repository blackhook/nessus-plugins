#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:008. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(12448);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2003-0989", "CVE-2004-0055", "CVE-2004-0057");
  script_xref(name:"RHSA", value:"2004:008");

  script_name(english:"RHEL 2.1 / 3 : tcpdump (RHSA-2004:008)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tcpdump, libpcap, and arpwatch packages fix vulnerabilities in
ISAKMP and RADIUS parsing.

[Updated 15 Jan 2004] Updated the text description to better describe
the vulnerabilities found by Jonathan Heusser and give them CVE names.

Tcpdump is a command-line tool for monitoring network traffic.

George Bakos discovered flaws in the ISAKMP decoding routines of
tcpdump versions prior to 3.8.1. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2003-0989
to this issue.

Jonathan Heusser discovered an additional flaw in the ISAKMP decoding
routines for tcpdump 3.8.1 and earlier. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2004-0057
to this issue.

Jonathan Heusser discovered a flaw in the print_attr_string function
in the RADIUS decoding routines for tcpdump 3.8.1 and earlier. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0055 to this issue.

Remote attackers could potentially exploit these issues by sending
carefully-crafted packets to a victim. If the victim uses tcpdump,
these pakets could result in a denial of service, or possibly execute
arbitrary code as the 'pcap' user.

Users of tcpdump are advised to upgrade to these erratum packages,
which contain backported security patches and are not vulnerable to
these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2003-0989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-0055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-0057"
  );
  # http://marc.theaimsgroup.com/?l=tcpdump-workers&m=107325073018070
  script_set_attribute(
    attribute:"see_also",
    value:"https://marc.info/?l=tcpdump-workers&m=107325073018070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2004:008"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected arpwatch, libpcap and / or tcpdump packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:arpwatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpcap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tcpdump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(2\.1|3)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if (cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i386", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:008";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"arpwatch-2.1a11-12.2.1AS.5")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"libpcap-0.6.2-12.2.1AS.5")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"tcpdump-3.6.2-12.2.1AS.5")) flag++;

  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"libpcap-0.7.2-7.E3.1")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"tcpdump-3.7.2-7.E3.1")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "arpwatch / libpcap / tcpdump");
  }
}
