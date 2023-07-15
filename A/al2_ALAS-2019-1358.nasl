#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1358.
#

include("compat.inc");

if (description)
{
  script_id(131026);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/12");

  script_cve_id("CVE-2018-1000876", "CVE-2018-12641", "CVE-2018-12697");
  script_xref(name:"ALAS", value:"2019-1358");

  script_name(english:"Amazon Linux 2 : binutils (ALAS-2019-1358)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An issue was discovered in arm_pt in cplus-dem.c in GNU libiberty, as
distributed in GNU Binutils 2.30. Stack Exhaustion occurs in the C++
demangling functions provided by libiberty, and there are recursive
stack frames: demangle_arm_hp_template, demangle_class_name,
demangle_fund_type, do_type, do_arg, demangle_args, and
demangle_nested_args. This can occur during execution of nm-new.
(CVE-2018-12641)

A NULL pointer dereference (aka SEGV on unknown address
0x000000000000) was discovered in work_stuff_copy_to_from in
cplus-dem.c in GNU libiberty, as distributed in GNU Binutils 2.30.
This can occur during execution of objdump. (CVE-2018-12697)

binutils version 2.32 and earlier contains a Integer Overflow
vulnerability in objdump,
bfd_get_dynamic_reloc_upper_bound,bfd_canonicalize_dynamic_reloc that
can result in Integer overflow trigger heap overflow. Successful
exploitation allows execution of arbitrary code.. This attack appear
to be exploitable via Local. This vulnerability appears to have been
fixed in after commit 3a551c7a1b80fca579461774860574eabfd7f18f.
(CVE-2018-1000876)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1358.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update binutils' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000876");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", reference:"binutils-2.29.1-29.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"binutils-debuginfo-2.29.1-29.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"binutils-devel-2.29.1-29.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils / binutils-debuginfo / binutils-devel");
}
