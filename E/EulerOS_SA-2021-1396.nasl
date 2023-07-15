#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147614);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/06");

  script_cve_id(
    "CVE-2015-8704",
    "CVE-2016-9147",
    "CVE-2016-9444",
    "CVE-2017-3135",
    "CVE-2017-3137",
    "CVE-2020-8625"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : bind (EulerOS-SA-2021-1396)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the bind packages installed, the EulerOS
Virtualization for ARM 64 installation on the remote host is affected
by the following vulnerabilities :

  - BIND (Berkeley Internet Name Domain) is an
    implementation of the DNS (Domain Name System)
    protocols. BIND includes a DNS server (named), which
    resolves host names to IP addresses a resolver library
    (routines for applications to use when interfacing with
    DNS) and tools for verifying that the DNS server is
    operating properly.Security Fix(es):A buffer overflow
    flaw was found in the SPNEGO implementation used by
    BIND. This flaw allows a remote attacker to cause the
    named process to crash or possibly perform remote code
    execution. The highest threat from this vulnerability
    is to confidentiality, integrity, as well as system
    availability.(CVE-2020-8625)named in ISC BIND 9.9.9-P4,
    9.9.9-S6, 9.10.4-P4, and 9.11.0-P1 allows remote
    attackers to cause a denial of service (assertion
    failure and daemon exit) via a response containing an
    inconsistency among the DNSSEC-related
    RRsets.(CVE-2016-9147)Under some conditions when using
    both DNS64 and RPZ to rewrite query responses, query
    processing can resume in an inconsistent state leading
    to either an INSIST assertion failure or an attempt to
    read through a NULL pointer. Affects BIND 9.8.8,
    9.9.3-S1 -> 9.9.9-S7, 9.9.3 -> 9.9.9-P5, 9.9.10b1,
    9.10.0 -> 9.10.4-P5, 9.10.5b1, 9.11.0 -> 9.11.0-P2,
    9.11.1b1.(CVE-2017-3135)Mistaken assumptions about the
    ordering of records in the answer section of a response
    containing CNAME or DNAME resource records could lead
    to a situation in which named would exit with an
    assertion failure when processing a response in which
    records occurred in an unusual order. Affects BIND
    9.9.9-P6, 9.9.10b1->9.9.10rc1, 9.10.4-P6,
    9.10.5b1->9.10.5rc1, 9.11.0-P3, 9.11.1b1->9.11.1rc1,
    and 9.9.9-S8.(CVE-2017-3137)apl_42.c in ISC BIND 9.x
    before 9.9.8-P3, 9.9.x, and 9.10.x before 9.10.3-P3
    allows remote authenticated users to cause a denial of
    service (INSIST assertion failure and daemon exit) via
    a malformed Address Prefix List (APL)
    record.(CVE-2015-8704)named in ISC BIND 9.x before
    9.9.9-P5, 9.10.x before 9.10.4-P5, and 9.11.x before
    9.11.0-P2 allows remote attackers to cause a denial of
    service (assertion failure and daemon exit) via a
    crafted DS resource record in an answer.(CVE-2016-9444)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1396
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4163433b");
  script_set_attribute(attribute:"solution", value:
"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["bind-libs-9.9.4-61.1.h14",
        "bind-libs-lite-9.9.4-61.1.h14",
        "bind-license-9.9.4-61.1.h14",
        "bind-utils-9.9.4-61.1.h14"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind");
}
