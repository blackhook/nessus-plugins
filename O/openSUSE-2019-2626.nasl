#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2626.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131688);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2019-18277");

  script_name(english:"openSUSE Security Update : haproxy (openSUSE-2019-2626)");
  script_summary(english:"Check for the openSUSE-2019-2626 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for haproxy to version 2.0.10 fixes the following issues :

HAProxy was updated to 2.0.10 &#9; 

Security issues fixed :

  - CVE-2019-18277: Fixed a potential HTTP smuggling in
    messages with transfer-encoding header missing the
    'chunked' (bsc#1154980).

  - Fixed an improper handling of headers which could have
    led to injecting LFs in H2-to-H1 transfers creating new
    attack space (bsc#1157712)

  - Fixed an issue where HEADER frames in idle streams are
    not rejected and thus trying to decode them HAPrpxy
    crashes (bsc#1157714).

Other issue addressed :

  - Macro change in the spec file (bsc#1082318)

More information regarding the release at:
http://git.haproxy.org/?p=haproxy-2.0.git;a=commit;h=ac198b92d46151555
1b95daae20954b3053ce87e

This update was imported from the SUSE:SLE-15:Update update project."
  );
  # http://git.haproxy.org/?p=haproxy-2.0.git;a=commit;h=ac198b92d461515551b95daae20954b3053ce87e
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e2d3256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157714"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected haproxy packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:haproxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:haproxy-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"haproxy-2.0.10+git0.ac198b92-lp150.2.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"haproxy-debuginfo-2.0.10+git0.ac198b92-lp150.2.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"haproxy-debugsource-2.0.10+git0.ac198b92-lp150.2.16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "haproxy / haproxy-debuginfo / haproxy-debugsource");
}
