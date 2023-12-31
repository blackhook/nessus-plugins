#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1154 and 
# CentOS Errata and Security Advisory 2015:1154 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84348);
  script_version("2.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-3204");
  script_bugtraq_id(75392);
  script_xref(name:"RHSA", value:"2015:1154");

  script_name(english:"CentOS 7 : libreswan (CESA-2015:1154)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libreswan packages that fix one security issue, several bugs
and add two enhancements are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Libreswan is an implementation of IPsec & IKE for Linux. IPsec is the
Internet Protocol Security and uses strong cryptography to provide
both authentication and encryption services. These services allow you
to build secure tunnels through untrusted networks such as virtual
private network (VPN).

A flaw was discovered in the way Libreswan's IKE daemon processed
certain IKEv1 payloads. A remote attacker could send specially crafted
IKEv1 payloads that, when processed, would lead to a denial of service
(daemon crash). (CVE-2015-3204)

Red Hat would like to thank Javantea for reporting this issue.

This update fixes the following bugs :

* Previously, the programs/pluto/state.h and
programs/pluto/kernel_netlink.c files had a maximum SELinux context
size of 257 and 1024 respectively. These restrictions set by libreswan
limited the size of the context that can be exchanged by pluto (the
IPSec daemon) when using a Labeled Internet Protocol Security (IPsec).
The SElinux labels for Labeled IPsec have been extended to 4096 bytes
and the mentioned restrictions no longer exist. (BZ#1198650)

* On some architectures, the kernel AES_GCM IPsec algorithm did not
work properly with acceleration drivers. On those kernels, some
acceleration modules are added to the modprobe blacklist. However,
Libreswan was ignoring this blacklist, leading to AES_GCM failures.
This update adds support for the module blacklist to the libreswan
packages and thus prevents the AES_GCM failures from occurring.
(BZ#1208022)

* An IPv6 issue has been resolved that prevented ipv6-icmp Neighbour
Discovery from working properly once an IPsec tunnel is established
(and one endpoint reboots). When upgrading, ensure that
/etc/ipsec.conf is loading all /etc/ipsec.d/*conf files using the
/etc/ipsec.conf 'include' statement, or explicitly include this new
configuration file in /etc/ipsec.conf. (BZ#1208023)

* A FIPS self-test prevented libreswan from properly starting in FIPS
mode. This bug has been fixed and libreswan now works in FIPS mode as
expected. (BZ#1211146)

In addition, this update adds the following enhancements :

* A new option 'seedbits=' has been added to pre-seed the Network
Security Services (NSS) pseudo random number generator (PRNG) function
with entropy from the /dev/random file on startup. This option is
disabled by default. It can be enabled by setting the 'seedbits='
option in the 'config setup' section in the /etc/ipsec.conf file.
(BZ#1198649)

* The build process now runs a Cryptographic Algorithm Validation
Program (CAVP) certification test on the Internet Key Exchange version
1 and 2 (IKEv1 and IKEv2) PRF/PRF+ functions. (BZ#1213652)

All libreswan users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-June/021205.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e78c1faf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libreswan package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3204");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreswan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreswan-3.12-10.1.el7_1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libreswan");
}
