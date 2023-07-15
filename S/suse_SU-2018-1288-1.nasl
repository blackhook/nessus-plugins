#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1288-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(109859);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-1000041");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : librsvg (SUSE-SU-2018:1288-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for librsvg fixes the following issues :

  - CVE-2018-1000041: Input validation issue could lead to
    credentials leak. (bsc#1083232) Update to version
    2.40.20 :

  + Except for emergencies, this will be the LAST RELEASE of
    the librsvg-2.40.x series. We are moving to 2.41, which
    is vastly improved over the 2.40 series. The API/ABI
    there remain unchaged, so we strongly encourage you to
    upgrade your sources and binaries to librsvg-2.41.x.

  + bgo#761175 - Allow masks and clips to reuse a node being
    drawn.

  + Don't access the file system when deciding whether to
    load a remote file with a UNC path for a paint server
    (i.e. don't try to load it at all).

  + Vistual Studio: fixed and integrated introspection
    builds, so introspection data is built directly from the
    Visual Studio project (Chun-wei Fan).

  + Visual Studio: We now use HIGHENTROPYVA linker option on
    x64 builds, to enhance the security of built binaries
    (Chun-wei Fan).

  + Fix generation of Vala bindings when compiling in
    read-only source directories (Emmanuele Bassi). Update
    to version 2.40.19 :

  + bgo#621088: Using text objects as clipping paths is now
    supported.

  + bgo#587721: Fix rendering of text elements with
    transformations (Massimo).

  + bgo#777833 - Fix memory leaks when an RsvgHandle is
    disposed before being closed (Philip Withnall).

  + bgo#782098 - Don't pass deprecated options to gtk-doc
    (Ting-Wei Lan).

  + bgo#786372 - Fix the default for the 'type' attribute of
    the <style> element.

  + bgo#785276 - Don't crash on single-byte files.

  + bgo#634514: Don't render unknown elements and their
    sub-elements.

  + bgo#777155 - Ignore patterns that have close-to-zero
    dimensions.

  + bgo#634324 - Fix Gaussian blurs with negative scaling.

  + Fix the <switch> element; it wasn't working at all.

  + Fix loading when rsvg_handle_write() is called one byte
    at a time.

  + bgo#787895 - Fix incorrect usage of libxml2. Thanks to
    Nick Wellnhofer for advice on this.

  + Backported the test suite machinery from the master
    branch (Chun-wei Fan, Federico Mena).

  + We now require Pango 1.38.0 or later (released in 2015).

  + We now require libxml2 2.9.0 or later (released in
    2012).

</style>

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1083232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-1000041/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181288-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7079b4db"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-912=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-912=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-912=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gdk-pixbuf-loader-rsvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gdk-pixbuf-loader-rsvg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librsvg-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librsvg-2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librsvg-2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librsvg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsvg-view");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsvg-view-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"gdk-pixbuf-loader-rsvg-2.40.20-5.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"gdk-pixbuf-loader-rsvg-debuginfo-2.40.20-5.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librsvg-2-2-2.40.20-5.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librsvg-2-2-32bit-2.40.20-5.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librsvg-2-2-debuginfo-2.40.20-5.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librsvg-2-2-debuginfo-32bit-2.40.20-5.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"librsvg-debugsource-2.40.20-5.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"rsvg-view-2.40.20-5.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"rsvg-view-debuginfo-2.40.20-5.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gdk-pixbuf-loader-rsvg-2.40.20-5.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gdk-pixbuf-loader-rsvg-debuginfo-2.40.20-5.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"librsvg-2-2-2.40.20-5.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"librsvg-2-2-32bit-2.40.20-5.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"librsvg-2-2-debuginfo-2.40.20-5.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"librsvg-2-2-debuginfo-32bit-2.40.20-5.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"librsvg-debugsource-2.40.20-5.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"rsvg-view-2.40.20-5.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"rsvg-view-debuginfo-2.40.20-5.6.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "librsvg");
}
