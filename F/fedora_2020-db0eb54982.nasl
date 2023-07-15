#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-db0eb54982.
#

include("compat.inc");

if (description)
{
  script_id(144729);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2020-29651");
  script_xref(name:"FEDORA", value:"2020-db0eb54982");

  script_name(english:"Fedora 32 : python-py (2020-db0eb54982)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"#### 1.10.0 (2020-12-12) ####

  - Fix a regular expression DoS vulnerability in the
    py.path.svnwc SVN blame functionality (CVE-2020-29651)

  - Update vendored apipkg: 1.4 => 1.5

  - Update vendored iniconfig: 1.0.0 => 1.1.1

#### 1.9.0 (2020-06-24) ####

  - Add type annotation stubs for the following modules :

  - ``py.error``

  - ``py.iniconfig``

  - ``py.path`` (not including SVN paths)

  - ``py.io``

  - ``py.xml``

    There are no plans to type other modules at this time.

    The type annotations are provided in external .pyi
    files, not inline in the code, and may therefore contain
    small errors or omissions. If you use ``py`` in
    conjunction with a type checker, and encounter any type
    errors you believe should be accepted, please report it
    in an issue.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-db0eb54982"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected python-py package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python-py");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:32");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^32([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 32", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC32", reference:"python-py-1.10.0-1.fc32")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-py");
}
