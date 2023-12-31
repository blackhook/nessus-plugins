#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0354 and 
# CentOS Errata and Security Advisory 2009:0354 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(38893);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-0547", "CVE-2009-0582", "CVE-2009-0587");
  script_bugtraq_id(33720, 34100, 34109);
  script_xref(name:"RHSA", value:"2009:0354");

  script_name(english:"CentOS 4 : evolution-data-server (CESA-2009:0354)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated evolution-data-server and evolution28-evolution-data-server
packages that fix multiple security issues are now available for Red
Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Evolution Data Server provides a unified back-end for applications
which interact with contacts, task, and calendar information.
Evolution Data Server was originally developed as a back-end for
Evolution, but is now used by multiple other applications.

Evolution Data Server did not properly check the Secure/Multipurpose
Internet Mail Extensions (S/MIME) signatures used for public key
encryption and signing of e-mail messages. An attacker could use this
flaw to spoof a signature by modifying the text of the e-mail message
displayed to the user. (CVE-2009-0547)

It was discovered that Evolution Data Server did not properly validate
NTLM (NT LAN Manager) authentication challenge packets. A malicious
server using NTLM authentication could cause an application using
Evolution Data Server to disclose portions of its memory or crash
during user authentication. (CVE-2009-0582)

Multiple integer overflow flaws which could cause heap-based buffer
overflows were found in the Base64 encoding routines used by Evolution
Data Server. This could cause an application using Evolution Data
Server to crash, or, possibly, execute an arbitrary code when large
untrusted data blocks were Base64-encoded. (CVE-2009-0587)

All users of evolution-data-server and
evolution28-evolution-data-server are advised to upgrade to these
updated packages, which contain backported patches to correct these
issues. All running instances of Evolution Data Server and
applications using it (such as Evolution) must be restarted for the
update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-March/015681.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8fc5c78"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015900.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da15765b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015901.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7462337e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evolution-data-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 189, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution28-evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution28-evolution-data-server-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"evolution28-evolution-data-server-1.8.0-37.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"evolution28-evolution-data-server-devel-1.8.0-37.el4_7.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evolution28-evolution-data-server / etc");
}
