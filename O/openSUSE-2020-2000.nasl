#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2000.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(143225);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/17");

  script_cve_id("CVE-2019-16770", "CVE-2019-5418", "CVE-2019-5419", "CVE-2019-5420", "CVE-2020-11076", "CVE-2020-11077", "CVE-2020-15169", "CVE-2020-5247", "CVE-2020-5249", "CVE-2020-5267", "CVE-2020-8164", "CVE-2020-8165", "CVE-2020-8166", "CVE-2020-8167", "CVE-2020-8184", "CVE-2020-8185");

  script_name(english:"openSUSE Security Update : rmt-server (openSUSE-2020-2000)");
  script_summary(english:"Check for the openSUSE-2020-2000 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for rmt-server fixes the following issues :

  - Version 2.6.5

  - Solved potential bug of SCC repository URLs changing
    over time. RMT now self heals by removing the previous
    invalid repository and creating the correct one.

  - Version 2.6.4

  - Add web server settings to /etc/rmt.conf: Now it's
    possible to configure the minimum and maximum threads
    count as well the number of web server workers to be
    booted through /etc/rmt.conf.

  - Version 2.6.3

  - Instead of using an MD5 of URLs for custom repository
    friendly_ids, RMT now builds an ID from the name.

  - Version 2.6.2

  - Fix RMT file caching based on timestamps: Previously,
    RMT sent GET requests with the header
    'If-Modified-Since' to a repository server and if the
    response had a 304 (Not Modified), it would copy a file
    from the local cache instead of downloading. However, if
    the local file timestamp accidentally changed to a date
    newer than the one on the repository server, RMT would
    have an outdated file, which caused some errors. Now,
    RMT makes HEAD requests to the repositories servers and
    inspect the 'Last-Modified' header to decide whether to
    download a file or copy it from cache, by comparing the
    equalness of timestamps.



  - Version 2.6.1

  - Fixed an issue where relative paths supplied to `rmt-cli
    import repos` caused the command to fail.

  - Version 2.6.0

  - Friendlier IDs for custom repositories: In an effort to
    simplify the handling of SCC and custom repositories,
    RMT now has friendly IDs. For SCC repositories, it's the
    same SCC ID as before. For custom repositories, it can
    either be user provided or RMT generated (MD5 of the
    provided URL). Benefits :

  - `rmt-cli mirror repositories` now works for custom
    repositories.

  - Custom repository IDs can be the same across RMT
    instances.

  - No more confusing 'SCC ID' vs 'ID' in `rmt-cli` output.
    Deprecation Warnings :

  - RMT now uses a different ID for custom repositories than
    before. RMT still supports that old ID, but it's
    recommended to start using the new ID to ensure future
    compatibility.

  - Version 2.5.20

  - Updated rails from 6.0.3.2 to 6.0.3.3 :

  - actionview (CVE-2020-15169)

  - Version 2.5.19

  - RMT now has the ability to remove local systems with the
    command `rmt-cli systems remove`.

  - Version 2.5.18

  - Fixed exit code for `rmt-cli mirror` and its
    subcommands. Now it exits with 1 whenever an error
    occurs during mirroring

  - Improved message logging for `rtm-cli mirror`. Instead
    of logging an error when it occurs, the command
    summarize all errors at the end of execution. Now log
    messages have colors to better identify failure/success.

  - Version 2.5.17

  - RMT no longer provides the installer updates repository
    to systems via its zypper service. This repository is
    used during the installation process, as it provides an
    up-to-date installation experience, but it has no use on
    an already installed system.

  - Version 2.5.16

  - Updated RMT's rails and puma dependencies.

  - puma (CVE-2020-11076, CVE-2020-11077, CVE-2020-5249,
    CVE-2020-5247 CVE-2019-16770)

  - actionpack (CVE-2020-8185, CVE-2020-8164, CVE-2020-8166)

  - actionview (CVE-2020-8167, CVE-2020-5267, CVE-2019-5418,
    CVE-2019-5419)

  - activesupport (CVE-2020-8165)

  - railties (CVE-2019-5420)

  - Version 2.5.15

  - RMT now checks if repositories are fully mirrored during
    the activation process. Previously, RMT only checked if
    the repositories were enabled to be mirrored, but not
    that they were actually mirrored. In this case, RMTs
    were not able to provide the repository data which
    systems assumed it had.

  - Version 2.5.14

  - Enable 'Installer-Updates' repositories by default

  - Fixed deprecation warning when thor encountered an
    error. Also, instead of returning 0 for thor errors,
    rmt-cli will return 1 instead.

  - Version 2.5.13

  - Added `rmt-cli repos clean` command to remove locally
    mirrored files of repositories which are not marked to
    be mirrored.

  - Previously, RMT didn't track deduplicated files in its
    database. Now, to accommodate `rmt-cli repos clean`, RMT
    will track all mirrored files.

  - Move the nginx reload to the configuration package which
    contain nginx config files, don't reload nginx
    unconditionally from main package.

  - Version 2.5.12

  - Update rack to version 2.2.3 (CVE-2020-8184:
    bsc#1173351)

  - Update Rails to version 5.2.4.3 :

  - actionpack (CVE-2020-8164: bsc#1172177)

  - actionpack (CVE-2020-8166: bsc#1172182)

  - activesupport (CVE-2020-8165: bsc#1172186)

  - actionview (CVE-2020-8167: bsc#1172184)

  - Version 2.5.11

  - rmt-server-pubcloud :

  - SLES11 EOL

  - Extension activation verification based on the available
    subscriptions

  - Added a manual instance verification script

  - Version 2.5.10

  - Support rmt-server to run with Ruby 2.7
    (Factory/Tumbleweed) :

  - Bump gem 'config' version from 1.7.2 to 2.2.1 to fix
    incompatibility Ruby 2.7 OpenStruct class;

  - Bump gem 'typhoeus' version from 1.3.1 to 1.4.0 in order
    to also bump gem 'ethon' version, which caused a
    'rb_safe_level' warning on Ruby 2.7;

  - Fix 'last arg as keyword arg' Ruby 2.7 warning on source
    code;

  - Disable 'deprecated' warnings from Ruby 2.7; Rails 5.1
    generates a lot of warnings with Ruby 2.7, mainly due to
    'capturing the given block with Proc.new', which is
    deprecated;

  - Improve RPM spec to consider only the distribution
    default Ruby version configured in OBS;

  - Improve RPM spec to remove Ruby 2.7 warnings regarding
    'bundler.

  - Move nginx/vhosts.d directory to correct sub-package.
    They are needed together with nginx, not rmt-server.

  - Fix dependencies especially for containerized usage :

  - mariadb and nginx are not hard requires, could run on
    another host

  - Fix generic dependencies :

  - systemd ordering was missing

  - shadow is required for pre-install

  - Version 2.5.9

  - rmt-server-pubcloud: enforce strict authentication

  - Version 2.5.8

  - Use repomd_parser gem to remove repository metadata
    parsing code.

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173351"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected rmt-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8165");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Rails File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ruby On Rails DoubleTap Development Mode secret_key_base Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rmt-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rmt-server-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rmt-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rmt-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rmt-server-pubcloud");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"rmt-server-2.6.5-lp151.2.18.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rmt-server-config-2.6.5-lp151.2.18.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rmt-server-debuginfo-2.6.5-lp151.2.18.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rmt-server-debugsource-2.6.5-lp151.2.18.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rmt-server-pubcloud-2.6.5-lp151.2.18.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rmt-server / rmt-server-config / rmt-server-debuginfo / etc");
}
