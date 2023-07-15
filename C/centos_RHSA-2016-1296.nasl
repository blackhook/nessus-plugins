#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1296 and 
# CentOS Errata and Security Advisory 2016:1296 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91788);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-8869");
  script_xref(name:"RHSA", value:"2016:1296");

  script_name(english:"CentOS 7 : ocaml (CESA-2016:1296)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ocaml is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

OCaml is a high-level, strongly-typed, functional, and object-oriented
programming language from the ML family of languages. The ocaml
packages contain two batch compilers (a fast bytecode compiler and an
optimizing native-code compiler), an interactive top level system,
parsing tools (Lex, Yacc, Camlp4), a replay debugger, a documentation
generator, and a comprehensive library.

Security Fix(es) :

* OCaml versions 4.02.3 and earlier have a runtime bug that, on 64-bit
platforms, causes size arguments to internal memmove calls to be
sign-extended from 32- to 64-bits before being passed to the memmove
function. This leads to arguments between 2GiB and 4GiB being
interpreted as larger than they are (specifically, a bit below 2^64),
causing a buffer overflow. Further, arguments between 4GiB and 6GiB
are interpreted as 4GiB smaller than they should be, causing a
possible information leak. (CVE-2015-8869)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-June/021933.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65ad8f14"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ocaml packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8869");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-camlp4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-camlp4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-compiler-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-labltk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-labltk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-ocamldoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ocaml-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ocaml-camlp4-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ocaml-camlp4-devel-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ocaml-compiler-libs-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ocaml-docs-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ocaml-emacs-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ocaml-labltk-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ocaml-labltk-devel-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ocaml-ocamldoc-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ocaml-runtime-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ocaml-source-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ocaml-x11-4.01.0-22.7.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ocaml / ocaml-camlp4 / ocaml-camlp4-devel / ocaml-compiler-libs / etc");
}
