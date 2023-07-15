#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1401.
#

include("compat.inc");

if (description)
{
  script_id(134329);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/11");

  script_cve_id("CVE-2019-14378");
  script_xref(name:"ALAS", value:"2020-1401");

  script_name(english:"Amazon Linux 2 : qemu (ALAS-2020-1401)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ip_reass in ip_input.c in libslirp 4.0.0 has a heap-based buffer
overflow via a large packet because it mishandles a case involving the
first fragment. (CVE-2019-14378)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1401.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update qemu' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ivshmem-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-audio-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-audio-oss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-audio-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-audio-sdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-block-dmg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-block-nfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-kvm-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-system-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-system-aarch64-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-system-x86-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-ui-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-ui-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-ui-sdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-user-binfmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-user-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/09");
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
if (rpm_check(release:"AL2", reference:"ivshmem-tools-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-audio-alsa-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-audio-oss-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-audio-pa-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-audio-sdl-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-block-curl-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-block-dmg-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-block-iscsi-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-block-nfs-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"qemu-block-rbd-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-block-ssh-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-common-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-debuginfo-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-guest-agent-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-img-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-kvm-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-kvm-core-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-system-aarch64-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-system-aarch64-core-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-system-x86-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-system-x86-core-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-ui-curses-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-ui-gtk-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-ui-sdl-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-user-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-user-binfmt-3.1.0-8.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"qemu-user-static-3.1.0-8.amzn2.0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ivshmem-tools / qemu / qemu-audio-alsa / qemu-audio-oss / etc");
}
