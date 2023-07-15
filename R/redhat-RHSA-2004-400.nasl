#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:400. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14696);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2004-0500", "CVE-2004-0754", "CVE-2004-0784", "CVE-2004-0785");
  script_xref(name:"RHSA", value:"2004:400");

  script_name(english:"RHEL 3 : gaim (RHSA-2004:400)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gaim package that fixes several security issues is now
available.

Gaim is an instant messenger client that can handle multiple
protocols.

Buffer overflow bugs were found in the Gaim MSN protocol handler. In
order to exploit these bugs, an attacker would have to perform a man
in the middle attack between the MSN server and the vulnerable Gaim
client. Such an attack could allow arbitrary code execution. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0500 to this issue.

Buffer overflow bugs have been found in the Gaim URL decoder, local
hostname resolver, and the RTF message parser. It is possible that a
remote attacker could send carefully crafted data to a vulnerable
client and lead to a crash or arbitrary code execution. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-0785 to this issue.

A shell escape bug has been found in the Gaim smiley theme file
installation. When a user installs a smiley theme, which is contained
within a tar file, the unarchiving of the data is done in an unsafe
manner. An attacker could create a malicious smiley theme that would
execute arbitrary commands if the theme was installed by the victim.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0784 to this issue.

An integer overflow bug has been found in the Gaim Groupware message
receiver. It is possible that if a user connects to a malicious
server, an attacker could send carefully crafted data which could lead
to arbitrary code execution on the victims machine. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-0754 to this issue.

Users of Gaim are advised to upgrade to this updated package which
contains Gaim version 0.82 and is not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-0500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-0754"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-0784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-0785"
  );
  # http://gaim.sourceforge.net/security/?id=0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.pidgin.im/news/security/?id=0"
  );
  # http://gaim.sourceforge.net/security/?id=1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.pidgin.im/news/security/?id=1"
  );
  # http://gaim.sourceforge.net/security/?id=2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.pidgin.im/news/security/?id=2"
  );
  # http://gaim.sourceforge.net/security/?id=3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.pidgin.im/news/security/?id=3"
  );
  # http://gaim.sourceforge.net/security/?id=4
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.pidgin.im/news/security/?id=4"
  );
  # http://gaim.sourceforge.net/security/?id=5
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.pidgin.im/news/security/?id=5"
  );
  # http://gaim.sourceforge.net/security/?id=6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.pidgin.im/news/security/?id=6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2004:400"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gaim package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gaim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/09");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:400";
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
  if (rpm_check(release:"RHEL3", reference:"gaim-0.82.1-0.RHEL3")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gaim");
  }
}
