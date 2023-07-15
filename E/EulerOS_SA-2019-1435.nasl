#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124938);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2013-0179",
    "CVE-2013-7239",
    "CVE-2013-7290",
    "CVE-2013-7291",
    "CVE-2016-8704",
    "CVE-2016-8705",
    "CVE-2016-8706",
    "CVE-2018-1000127"
  );
  script_bugtraq_id(
    64559,
    64978,
    64988,
    64989
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : memcached (EulerOS-SA-2019-1435)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the memcached package installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - memcached before 1.4.17, when running in verbose mode,
    allows remote attackers to cause a denial of service
    (crash) via a request that triggers an 'unbounded key
    print' during logging, related to an issue that was
    'quickly grepped out of the source tree,' a different
    vulnerability than CVE-2013-0179 and
    CVE-2013-7290.(CVE-2013-7291)

  - An integer overflow flaw, leading to a heap-based
    buffer overflow, was found in memcached's parsing of
    SASL authentication messages. An attacker could create
    a specially crafted message that would cause the
    memcached server to crash or, potentially, execute
    arbitrary code.(CVE-2016-8706)

  - An integer overflow flaw, leading to a heap-based
    buffer overflow, was found in the memcached binary
    protocol. An attacker could create a specially crafted
    message that would cause the memcached server to crash
    or, potentially, execute arbitrary code.(CVE-2016-8704)

  - The process_bin_delete function in memcached.c in
    memcached 1.4.4 and other versions before 1.4.17, when
    running in verbose mode, allows remote attackers to
    cause a denial of service (segmentation fault) via a
    request to delete a key, which does not account for the
    lack of a null terminator in the key and triggers a
    buffer over-read when printing to
    stderr.(CVE-2013-0179)

  - An integer overflow flaw, leading to a heap-based
    buffer overflow, was found in the memcached binary
    protocol. An attacker could create a specially crafted
    message that would cause the memcached server to crash
    or, potentially, execute arbitrary code.(CVE-2016-8705)

  - memcached version prior to 1.4.37 contains an Integer
    Overflow vulnerability in items.c:item_free() that can
    result in data corruption and deadlocks due to items
    existing in hash table being reused from free list.
    This attack appear to be exploitable via network
    connectivity to the memcached service. This
    vulnerability appears to have been fixed in 1.4.37 and
    later.(CVE-2018-1000127)

  - memcached before 1.4.17 allows remote attackers to
    bypass authentication by sending an invalid request
    with SASL credentials, then sending another request
    with incorrect SASL credentials.(CVE-2013-7239)

  - The do_item_get function in items.c in memcached 1.4.4
    and other versions before 1.4.17, when running in
    verbose mode, allows remote attackers to cause a denial
    of service (segmentation fault) via a request to delete
    a key, which does not account for the lack of a null
    terminator in the key and triggers a buffer over-read
    when printing to stderr, a different vulnerability than
    CVE-2013-0179.(CVE-2013-7290)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1435
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83766b3e");
  script_set_attribute(attribute:"solution", value:
"Update the affected memcached packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:memcached");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["memcached-1.4.15-10.1.h2.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "memcached");
}
