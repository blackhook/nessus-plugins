#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update gvim-561.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40230);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-2712", "CVE-2008-3074", "CVE-2008-3075", "CVE-2008-3076", "CVE-2008-4677", "CVE-2008-6235", "CVE-2009-0316");

  script_name(english:"openSUSE Security Update : gvim (gvim-561)");
  script_summary(english:"Check for the gvim-561 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The VI Improved editor (vim) was updated to version 7.2.108 to fix
various security problems and other bugs.

CVE-2008-4677: The netrw plugin sent credentials to all servers.
CVE-2009-0316: The python support used a search path including the
current directory, allowing code injection when python code was used.
CVE-2008-2712: Arbitrary code execution in vim helper plugins
filetype.vim, zipplugin, xpm.vim, gzip_vim, and netrw were fixed.
CVE-2008-3074: tarplugin code injection CVE-2008-3075: zipplugin code
injection CVE-2008-3076: several netrw bugs, code injection
CVE-2008-6235: code injection in the netrw plugin CVE-2008-4677:
credential disclosure by netrw plugin"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=406693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=436755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=439148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=457098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=465255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=470100"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gvim packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 78, 94, 255);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"gvim-7.2-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"vim-7.2-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"vim-base-7.2-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"vim-data-7.2-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"vim-enhanced-7.2-7.4.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim");
}
