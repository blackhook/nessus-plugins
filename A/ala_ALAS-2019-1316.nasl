#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1316.
#

include("compat.inc");

if (description)
{
  script_id(130609);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-13139", "CVE-2019-13509");
  script_xref(name:"ALAS", value:"2019-1316");

  script_name(english:"Amazon Linux AMI : docker (ALAS-2019-1316)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A command injection flaw was discovered in Docker during the `docker
build` command. By providing a specially crafted path argument for the
container to build, it is possible to inject command options to the
`git fetch`/`git checkout` commands that are executed by Docker and to
execute code with the privileges of the user running Docker. A local
attacker who can run `docker build` with a controlled build path, or a
remote attacker who has control over the docker build path, could
elevate their privileges or execute code.(CVE-2019-13139)

In Docker CE and EE before 18.09.8 (as well as Docker EE before
17.06.2-ee-23 and 18.x before 18.03.1-ee-10), Docker Engine in debug
mode may sometimes add secrets to the debug log. This applies to a
scenario where docker stack deploy is run to redeploy a stack that
includes (non external) secrets. It potentially applies to other API
users of the stack API if they resend the secret.(CVE-2019-13509)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1316.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update docker' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13509");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"docker-18.09.9ce-2.52.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"docker-debuginfo-18.09.9ce-2.52.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "docker / docker-debuginfo");
}
