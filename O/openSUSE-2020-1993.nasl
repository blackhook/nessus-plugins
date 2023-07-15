#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1993.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(143190);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/17");

  script_cve_id("CVE-2019-16770", "CVE-2019-5418", "CVE-2019-5419", "CVE-2019-5420", "CVE-2020-11076", "CVE-2020-11077", "CVE-2020-15169", "CVE-2020-5247", "CVE-2020-5249", "CVE-2020-5267", "CVE-2020-8164", "CVE-2020-8165", "CVE-2020-8166", "CVE-2020-8167", "CVE-2020-8184", "CVE-2020-8185");

  script_name(english:"openSUSE Security Update : rmt-server (openSUSE-2020-1993)");
  script_summary(english:"Check for the openSUSE-2020-1993 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for rmt-server fixes the following issues :

Update to version 2.6.5 :

  - Solved potential bug of SCC repository URLs changing
    over time. RMT now self heals by removing the previous
    invalid repository and creating the correct one.

  - Add web server settings to /etc/rmt.conf: Now it's
    possible to configure the minimum and maximum threads
    count as well the number of web server workers to be
    booted through /etc/rmt.conf.

  - Instead of using an MD5 of URLs for custom repository
    friendly_ids, RMT now builds an ID from the name.

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

  - Fixed an issue where relative paths supplied to `rmt-cli
    import repos` caused the command to fail.

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

  - Updated rails and puma dependencies for security fixes.

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168554"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/23");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"rmt-server-2.6.5-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rmt-server-config-2.6.5-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rmt-server-debuginfo-2.6.5-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rmt-server-debugsource-2.6.5-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rmt-server-pubcloud-2.6.5-lp152.2.3.1") ) flag++;

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
