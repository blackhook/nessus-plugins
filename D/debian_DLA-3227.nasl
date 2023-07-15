#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3227. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168449);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2022-32209");

  script_name(english:"Debian DLA-3227-1 : ruby-rails-html-sanitizer - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by a vulnerability as referenced in the dla-3227
advisory.

  - # Possible XSS Vulnerability in Rails::Html::SanitizerThere is a possible XSS vulnerability with certain
    configurations of Rails::Html::Sanitizer.This vulnerability has been assigned the CVE identifier
    CVE-2022-32209.Versions Affected: ALLNot affected: NONEFixed Versions: v1.4.3## ImpactA possible XSS
    vulnerability with certain configurations of Rails::Html::Sanitizer may allow an attacker to inject
    content if the application developer has overridden the sanitizer's allowed tags to allow both `select`
    and `style` elements.Code is only impacted if allowed tags are being overridden. This may be done via
    application configuration:```ruby# In config/application.rbconfig.action_view.sanitized_allowed_tags =
    [select, style]```see https://guides.rubyonrails.org/configuring.html#configuring-action-viewOr it may
    be done with a `:tags` option to the Action View helper `sanitize`:```<%= sanitize @comment.body, tags:
    [select, style] %>```see
    https://api.rubyonrails.org/classes/ActionView/Helpers/SanitizeHelper.html#method-i-sanitizeOr it may be
    done with Rails::Html::SafeListSanitizer directly:```ruby# class-level
    optionRails::Html::SafeListSanitizer.allowed_tags = [select, style]```or```ruby# instance-level
    optionRails::Html::SafeListSanitizer.new.sanitize(@article.body, tags: [select, style])```All users
    overriding the allowed tags by any of the above mechanisms to include both select and style should
    either upgrade or use one of the workarounds immediately.## ReleasesThe FIXED releases are available at
    the normal locations.## WorkaroundsRemove either `select` or `style` from the overridden allowed tags.##
    CreditsThis vulnerability was responsibly reported by
    [windshock](https://hackerone.com/windshock?type=user). (CVE-2022-32209)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1013806");
  # https://security-tracker.debian.org/tracker/source-package/ruby-rails-html-sanitizer
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?71ff2f68");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3227");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32209");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/ruby-rails-html-sanitizer");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ruby-rails-html-sanitizer packages.

For Debian 10 buster, this problem has been fixed in version 1.0.4-1+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32209");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-rails-html-sanitizer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'ruby-rails-html-sanitizer', 'reference': '1.0.4-1+deb10u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby-rails-html-sanitizer');
}
