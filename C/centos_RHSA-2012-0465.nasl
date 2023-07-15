#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0465 and 
# CentOS Errata and Security Advisory 2012:0465 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58663);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-1182");
  script_xref(name:"RHSA", value:"2012:0465");

  script_name(english:"CentOS 5 / 6 : samba (CESA-2012:0465)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6; Red Hat Enterprise Linux 5.3
Long Life; and Red Hat Enterprise Linux 5.6, 6.0 and 6.1 Extended
Update Support.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

A flaw in the Samba suite's Perl-based DCE/RPC IDL (PIDL) compiler,
used to generate code to handle RPC calls, resulted in multiple buffer
overflows in Samba. A remote, unauthenticated attacker could send a
specially crafted RPC request that would cause the Samba daemon (smbd)
to crash or, possibly, execute arbitrary code with the privileges of
the root user. (CVE-2012-1182)

Users of Samba are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing
this update, the smb service will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-April/018562.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d314040"
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-April/018565.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e85d5c5a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1182");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba SetInformationPolicy AuditEventsInfo Heap Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"libsmbclient-3.0.33-3.39.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libsmbclient-devel-3.0.33-3.39.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba-3.0.33-3.39.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba-client-3.0.33-3.39.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba-common-3.0.33-3.39.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba-swat-3.0.33-3.39.el5_8")) flag++;

if (rpm_check(release:"CentOS-6", reference:"libsmbclient-3.5.10-115.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsmbclient-devel-3.5.10-115.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-3.5.10-115.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-client-3.5.10-115.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-common-3.5.10-115.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-doc-3.5.10-115.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-domainjoin-gui-3.5.10-115.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-swat-3.5.10-115.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-winbind-3.5.10-115.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-winbind-clients-3.5.10-115.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-winbind-devel-3.5.10-115.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-winbind-krb5-locator-3.5.10-115.el6_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsmbclient / libsmbclient-devel / samba / samba-client / etc");
}
