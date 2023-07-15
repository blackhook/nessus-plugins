#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1408.
#

include("compat.inc");

if (description)
{
  script_id(139088);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/03");

  script_cve_id("CVE-2019-9824", "CVE-2020-7039", "CVE-2020-8608");
  script_xref(name:"ALAS", value:"2020-1408");

  script_name(english:"Amazon Linux AMI : qemu-kvm (ALAS-2020-1408)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"tcp_emu in slirp/tcp_subr.c (aka slirp/src/tcp_subr.c) in QEMU 3.0.0
uses uninitialized data in an snprintf call, leading to Information
disclosure. (CVE-2019-9824)

tcp_emu in tcp_subr.c in libslirp 4.1.0, as used in QEMU 4.2.0,
mismanages memory, as demonstrated by IRC DCC commands in EMU_IRC.
This can cause a heap-based buffer overflow or other out-of-bounds
access which can lead to a DoS or potential execute arbitrary code.
(CVE-2020-7039)

In libslirp 4.1.0, as used in QEMU 4.2.0, tcp_subr.c misuses snprintf
return values, leading to a buffer overflow in later code.
(CVE-2020-8608)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2020-1408.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update qemu-kvm' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/30");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"qemu-img-1.5.3-156.19.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"qemu-kvm-1.5.3-156.19.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"qemu-kvm-common-1.5.3-156.19.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"qemu-kvm-debuginfo-1.5.3-156.19.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"qemu-kvm-tools-1.5.3-156.19.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-img / qemu-kvm / qemu-kvm-common / qemu-kvm-debuginfo / etc");
}
