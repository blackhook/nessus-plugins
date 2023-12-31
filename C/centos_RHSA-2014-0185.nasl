#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0185 and 
# CentOS Errata and Security Advisory 2014:0185 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72561);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-6466");
  script_bugtraq_id(65155, 65629);
  script_xref(name:"RHSA", value:"2014:0185");

  script_name(english:"CentOS 5 / 6 : openswan (CESA-2014:0185)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openswan packages that fix one security issue are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Openswan is a free implementation of Internet Protocol Security
(IPsec) and Internet Key Exchange (IKE). IPsec uses strong
cryptography to provide both authentication and encryption services.
These services allow you to build secure tunnels through untrusted
networks.

A NULL pointer dereference flaw was discovered in the way Openswan's
IKE daemon processed IKEv2 payloads. A remote attacker could send
specially crafted IKEv2 payloads that, when processed, would lead to a
denial of service (daemon crash), possibly causing existing VPN
connections to be dropped. (CVE-2013-6466)

All openswan users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-February/020161.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?87a750f2"
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-February/020162.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?850c0edc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openswan packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-6466");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openswan-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"openswan-2.6.32-7.3.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openswan-doc-2.6.32-7.3.el5_10")) flag++;

if (rpm_check(release:"CentOS-6", reference:"openswan-2.6.32-27.2.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openswan-doc-2.6.32-27.2.el6_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openswan / openswan-doc");
}
