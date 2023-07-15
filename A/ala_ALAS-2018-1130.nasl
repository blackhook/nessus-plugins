#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1130.
#

include("compat.inc");

if (description)
{
  script_id(119689);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/27");

  script_cve_id("CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875");
  script_xref(name:"ALAS", value:"2018-1130");

  script_name(english:"Amazon Linux AMI : golang (ALAS-2018-1130)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In Go before 1.10.6 and 1.11.x before 1.11.3, the 'go get' command is
vulnerable to remote code execution when executed with the -u flag and
the import path of a malicious Go package, or a package that imports
it directly or indirectly. Specifically, it is only vulnerable in
GOPATH mode, but not in module mode (the distinction is documented at
https://golang.org/cmd/go/#hdr-Module_aware_go_get). Using custom
domains, it's possible to arrange things so that a Git repository is
cloned to a folder named '.git' by using a vanity import path that
ends with '/.git'. If the Git repository root contains a 'HEAD' file,
a 'config' file, an 'objects' directory, a 'refs' directory, with some
work to ensure the proper ordering of operations, 'go get -u' can be
tricked into considering the parent directory as a repository root,
and running Git commands on it. That will use the 'config' file in the
original Git repository root for its configuration, and if that config
file contains malicious commands, they will execute on the system
running 'go get -u'. (CVE-2018-16873)

The crypto/x509 package of Go before 1.10.6 and 1.11.x before 1.11.3
does not limit the amount of work performed for each chain
verification, which might allow attackers to craft pathological inputs
leading to a CPU denial of service. Go TLS servers accepting client
certificates and TLS clients are affected. (CVE-2018-16875)

In Go before 1.10.6 and 1.11.x before 1.11.3, the 'go get' command is
vulnerable to directory traversal when executed with the import path
of a malicious Go package which contains curly braces (both '{' and
'}' characters). Specifically, it is only vulnerable in GOPATH mode,
but not in module mode (the distinction is documented at
https://golang.org/cmd/go/#hdr-Module_aware_go_get). The attacker can
cause an arbitrary filesystem write, which can lead to code execution.
(CVE-2018-16874)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-1130.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update golang' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16874");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-race");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"golang-1.10.6-1.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-bin-1.10.6-1.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-docs-1.10.6-1.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-misc-1.10.6-1.47.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"golang-race-1.10.6-1.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-src-1.10.6-1.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-tests-1.10.6-1.47.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "golang / golang-bin / golang-docs / golang-misc / golang-race / etc");
}
