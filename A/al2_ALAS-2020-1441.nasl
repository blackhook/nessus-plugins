#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1441.
#

include("compat.inc");

if (description)
{
  script_id(138043);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/06");

  script_cve_id("CVE-2018-5745", "CVE-2019-6465", "CVE-2019-6477");
  script_xref(name:"ALAS", value:"2020-1441");

  script_name(english:"Amazon Linux 2 : bind (ALAS-2020-1441)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"'managed-keys' is a feature which allows a BIND resolver to
automatically maintain the keys used by trust anchors which operators
configure for use in DNSSEC validation. Due to an error in the
managed-keys feature it is possible for a BIND server which uses
managed-keys to exit due to an assertion failure if, during key
rollover, a trust anchor's keys are replaced with keys which use an
unsupported algorithm. Versions affected: BIND 9.9.0 -> 9.10.8-P1,
9.11.0 -> 9.11.5-P1, 9.12.0 -> 9.12.3-P1, and versions 9.9.3-S1 ->
9.11.5-S3 of BIND 9 Supported Preview Edition. Versions 9.13.0 ->
9.13.6 of the 9.13 development branch are also affected. Versions
prior to BIND 9.9.0 have not been evaluated for vulnerability to
CVE-2018-5745 . (CVE-2018-5745)

With pipelining enabled each incoming query on a TCP connection
requires a similar resource allocation to a query received via UDP or
via TCP without pipelining enabled. A client using a TCP-pipelined
connection to a server could consume more resources than the server
has been provisioned to handle. When a TCP connection with a large
number of pipelined queries is closed, the load on the server
releasing these multiple resources can cause it to become
unresponsive, even for queries that can be answered authoritatively or
from cache. (This is most likely to be perceived as an intermittent
server problem). (CVE-2019-6477)

Controls for zone transfers may not be properly applied to Dynamically
Loadable Zones (DLZs) if the zones are writable Versions affected:
BIND 9.9.0 -> 9.10.8-P1, 9.11.0 -> 9.11.5-P2, 9.12.0 -> 9.12.3-P2, and
versions 9.9.3-S1 -> 9.11.5-S3 of BIND 9 Supported Preview Edition.
Versions 9.13.0 -> 9.13.6 of the 9.13 development branch are also
affected. Versions prior to BIND 9.9.0 have not been evaluated for
vulnerability to CVE-2019-6465 . (CVE-2019-6465)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1441.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update bind' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6465");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-export-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"bind-9.11.4-9.P2.amzn2.0.4")) flag++;
if (rpm_check(release:"AL2", reference:"bind-chroot-9.11.4-9.P2.amzn2.0.4")) flag++;
if (rpm_check(release:"AL2", reference:"bind-debuginfo-9.11.4-9.P2.amzn2.0.4")) flag++;
if (rpm_check(release:"AL2", reference:"bind-devel-9.11.4-9.P2.amzn2.0.4")) flag++;
if (rpm_check(release:"AL2", reference:"bind-export-devel-9.11.4-9.P2.amzn2.0.4")) flag++;
if (rpm_check(release:"AL2", reference:"bind-export-libs-9.11.4-9.P2.amzn2.0.4")) flag++;
if (rpm_check(release:"AL2", reference:"bind-libs-9.11.4-9.P2.amzn2.0.4")) flag++;
if (rpm_check(release:"AL2", reference:"bind-libs-lite-9.11.4-9.P2.amzn2.0.4")) flag++;
if (rpm_check(release:"AL2", reference:"bind-license-9.11.4-9.P2.amzn2.0.4")) flag++;
if (rpm_check(release:"AL2", reference:"bind-lite-devel-9.11.4-9.P2.amzn2.0.4")) flag++;
if (rpm_check(release:"AL2", reference:"bind-pkcs11-9.11.4-9.P2.amzn2.0.4")) flag++;
if (rpm_check(release:"AL2", reference:"bind-pkcs11-devel-9.11.4-9.P2.amzn2.0.4")) flag++;
if (rpm_check(release:"AL2", reference:"bind-pkcs11-libs-9.11.4-9.P2.amzn2.0.4")) flag++;
if (rpm_check(release:"AL2", reference:"bind-pkcs11-utils-9.11.4-9.P2.amzn2.0.4")) flag++;
if (rpm_check(release:"AL2", reference:"bind-sdb-9.11.4-9.P2.amzn2.0.4")) flag++;
if (rpm_check(release:"AL2", reference:"bind-sdb-chroot-9.11.4-9.P2.amzn2.0.4")) flag++;
if (rpm_check(release:"AL2", reference:"bind-utils-9.11.4-9.P2.amzn2.0.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-debuginfo / bind-devel / etc");
}
