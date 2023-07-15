##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0070. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147296);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id(
    "CVE-2018-11805",
    "CVE-2019-12420",
    "CVE-2020-1930",
    "CVE-2020-1931"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : spamassassin Multiple Vulnerabilities (NS-SA-2021-0070)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has spamassassin packages installed that are affected by
multiple vulnerabilities:

  - In Apache SpamAssassin before 3.4.3, a message can be crafted in a way to use excessive resources.
    Upgrading to SA 3.4.3 as soon as possible is the recommended fix but details will not be shared publicly.
    (CVE-2019-12420)

  - A command execution issue was found in Apache SpamAssassin prior to 3.4.3. Carefully crafted nefarious
    rule configuration (.cf) files can be configured to run system commands similar to CVE-2018-11805. With
    this bug unpatched, exploits can be injected in a number of scenarios including the same privileges as
    spamd is run which may be elevated though doing so remotely is difficult. In addition to upgrading to SA
    3.4.4, we again recommend that users should only use update channels or 3rd party .cf files from trusted
    places. If you cannot upgrade, do not use 3rd party rulesets, do not use sa-compile and do not run spamd
    as an account with elevated privileges. (CVE-2020-1930)

  - A command execution issue was found in Apache SpamAssassin prior to 3.4.3. Carefully crafted nefarious
    Configuration (.cf) files can be configured to run system commands similar to CVE-2018-11805. This issue
    is less stealthy and attempts to exploit the issue will throw warnings. Thanks to Damian Lukowski at
    credativ for reporting the issue ethically. With this bug unpatched, exploits can be injected in a number
    of scenarios though doing so remotely is difficult. In addition to upgrading to SA 3.4.4, we again
    recommend that users should only use update channels or 3rd party .cf files from trusted places.
    (CVE-2020-1931)

  - In Apache SpamAssassin before 3.4.3, nefarious CF files can be configured to run system commands without
    any output or errors. With this, exploits can be injected in a number of scenarios. In addition to
    upgrading to SA 3.4.3, we recommend that users should only use update channels or 3rd party .cf files from
    trusted places. (CVE-2018-11805)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0070");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL spamassassin packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1931");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL MAIN 6.02': [
    'spamassassin-3.4.2-10.el8',
    'spamassassin-debuginfo-3.4.2-10.el8',
    'spamassassin-debugsource-3.4.2-10.el8'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'spamassassin');
}
