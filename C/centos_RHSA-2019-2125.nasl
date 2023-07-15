#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2125 and 
# CentOS Errata and Security Advisory 2019:2125 respectively.
#

include("compat.inc");

if (description)
{
  script_id(128356);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2017-5731", "CVE-2017-5732", "CVE-2017-5733", "CVE-2017-5734", "CVE-2017-5735", "CVE-2018-12181", "CVE-2018-3613", "CVE-2018-5407", "CVE-2019-0160", "CVE-2019-0161");
  script_xref(name:"RHSA", value:"2019:2125");

  script_name(english:"CentOS 7 : ovmf (CESA-2019:2125)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ovmf is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

OVMF (Open Virtual Machine Firmware) is a project to enable UEFI
support for Virtual Machines. This package contains a sample 64-bit
UEFI firmware for QEMU and KVM.

Security Fix(es) :

* edk2: Privilege escalation via processing of malformed files in
TianoCompress.c (CVE-2017-5731)

* edk2: Privilege escalation via processing of malformed files in
BaseUefiDecompressLib.c (CVE-2017-5732)

* edk2: Privilege escalation via heap-based buffer overflow in
MakeTable() function (CVE-2017-5733)

* edk2: Privilege escalation via stack-based buffer overflow in
MakeTable() function (CVE-2017-5734)

* edk2: Privilege escalation via heap-based buffer overflow in
Decode() function (CVE-2017-5735)

* edk2: Logic error in MdeModulePkg in EDK II firmware allows for
privilege escalation by authenticated users (CVE-2018-3613)

* openssl: Side-channel vulnerability on SMT/Hyper-Threading
architectures (PortSmash) (CVE-2018-5407)

* edk2: Stack buffer overflow with corrupted BMP (CVE-2018-12181)

* edk2: buffer overflows in PartitionDxe and UdfDxe with long file
names and invalid UDF media (CVE-2019-0160)

* edk2: stack overflow in XHCI causing denial of service
(CVE-2019-0161)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006035.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ecd7d721"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ovmf package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0160");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:OVMF");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"OVMF-20180508-6.gitee3198e672e2.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OVMF");
}
