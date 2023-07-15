#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1016.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103154);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-12791");
  script_xref(name:"IAVB", value:"2017-B-0112-S");

  script_name(english:"openSUSE Security Update : salt (openSUSE-2017-1016)");
  script_summary(english:"Check for the openSUSE-2017-1016 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for salt fixes the following issues :

  - Update to 2017.7.1 See
    https://docs.saltstack.com/en/develop/topics/releases/20
    17.7.1.html for full changelog

  - CVE-2017-12791: crafted minion ID could lead directory
    traversal on the Salt-master (boo#1053955)



  - Run fdupes over all of /usr because it still warns about
    duplicate files. Remove ancient suse_version > 1020
    conditional.

  - Replace unnecessary %__ indirections. Use grep -q in
    favor of >/dev/null.

  - Avoid bashisms in %pre.

  - Update to 2017.7.0 See
    https://docs.saltstack.com/en/develop/topics/releases/20
    17.7.0.html for full changelog

  - fix ownership for whole master cache directory
    (boo#1035914)

  - fix setting the language on SUSE systems (boo#1038855)

  - wrong os_family grains on SUSE - fix unittests
    (boo#1038855)

  - speed-up cherrypy by removing sleep call

  - Disable 3rd party runtime packages to be explicitly
    recommended. (boo#1040886)

  - fix format error (boo#1043111)

  - Add a salt-minion watchdog for RHEL6 and SLES11 systems
    (sysV) to restart salt-minion in case of crashes during
    upgrade.

  - Add procps as dependency.

  - Bugfix: jobs scheduled to run at a future time stay
    pending for Salt minions (boo#1036125)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.saltstack.com/en/develop/topics/releases/2017.7.0.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.saltstack.com/en/develop/topics/releases/2017.7.1.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected salt packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-fish-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-minion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-syndic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/13");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"salt-2017.7.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-api-2017.7.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-bash-completion-2017.7.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-cloud-2017.7.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-fish-completion-2017.7.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-master-2017.7.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-minion-2017.7.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-proxy-2017.7.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-ssh-2017.7.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-syndic-2017.7.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-zsh-completion-2017.7.1-11.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "salt / salt-api / salt-bash-completion / salt-cloud / etc");
}
