#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92031);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-8869");

  script_name(english:"Scientific Linux Security Update : ocaml on SL7.x x86_64 (20160623)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security Fix(es) :

  - OCaml versions 4.02.3 and earlier have a runtime bug
    that, on 64-bit platforms, causes size arguments to
    internal memmove calls to be sign- extended from 32- to
    64-bits before being passed to the memmove function.
    This leads to arguments between 2GiB and 4GiB being
    interpreted as larger than they are (specifically, a bit
    below 2^64), causing a buffer overflow. Further,
    arguments between 4GiB and 6GiB are interpreted as 4GiB
    smaller than they should be, causing a possible
    information leak. (CVE-2015-8869)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1607&L=scientific-linux-errata&F=&S=&P=75
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f60dc3b6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:brlapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:brlapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:brlapi-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:brltty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:brltty-at-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:brltty-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:brltty-xw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:graphviz-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:graphviz-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:graphviz-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:graphviz-graphs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:graphviz-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:graphviz-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:graphviz-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:graphviz-ocaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:graphviz-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:graphviz-php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:graphviz-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:graphviz-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:graphviz-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-brlapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-calendar-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-camlp4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-camlp4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-compiler-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-csv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-csv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-curses-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-extlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-extlib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-fileutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-fileutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-findlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-findlib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-gettext-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-labltk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-labltk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-ocamldoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-xml-light");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ocaml-xml-light-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-brlapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tcl-brlapi");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"brlapi-0.6.0-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"brlapi-devel-0.6.0-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"brlapi-java-0.6.0-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"brltty-4.5-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"brltty-at-spi-4.5-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"brltty-docs-4.5-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"brltty-xw-4.5-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-devel-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-doc-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-gd-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-graphs-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-guile-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-java-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-lua-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-ocaml-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-perl-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-php-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-python-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-ruby-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-tcl-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"hivex-1.3.10-5.7.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"hivex-devel-1.3.10-5.7.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-brlapi-0.6.0-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-calendar-2.03.2-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-calendar-devel-2.03.2-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-camlp4-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-camlp4-devel-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-compiler-libs-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-csv-1.2.3-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-csv-devel-1.2.3-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-curses-1.0.3-18.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-curses-devel-1.0.3-18.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-debuginfo-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-docs-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-emacs-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-extlib-1.5.3-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-extlib-devel-1.5.3-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-fileutils-0.4.4-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-fileutils-devel-0.4.4-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-findlib-1.3.3-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-findlib-devel-1.3.3-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-gettext-0.3.4-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-gettext-devel-0.3.4-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-hivex-1.3.10-5.7.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-hivex-devel-1.3.10-5.7.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-labltk-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-labltk-devel-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-libguestfs-devel-1.28.1-1.18.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-libvirt-0.6.1.2-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-libvirt-devel-0.6.1.2-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-ocamldoc-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-runtime-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-source-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-x11-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-xml-light-2.3-0.6.svn234.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-xml-light-devel-2.3-0.6.svn234.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perl-hivex-1.3.10-5.7.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-brlapi-0.6.0-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-hivex-1.3.10-5.7.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-hivex-1.3.10-5.7.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tcl-brlapi-0.6.0-9.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "brlapi / brlapi-devel / brlapi-java / brltty / brltty-at-spi / etc");
}
