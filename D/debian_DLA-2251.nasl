#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2251-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137670);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2020-8164", "CVE-2020-8165");

  script_name(english:"Debian DLA-2251-1 : rails security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Two vulnerabilities were found in Ruby on Rails, a MVC ruby-based
framework geared for web application development, which could lead to
remote code execution and untrusted user input usage, depending on the
application.

CVE-2020-8164

Strong parameters bypass vector in ActionPack. In some cases user
supplied information can be inadvertently leaked from Strong
Parameters. Specifically the return value of `each`, or `each_value`,
or `each_pair` will return the underlying 'untrusted' hash of data
that was read from the parameters. Applications that use this return
value may be inadvertently use untrusted user input.

CVE-2020-8165

Potentially unintended unmarshalling of user-provided objects in
MemCacheStore. There is potentially unexpected behaviour in the
MemCacheStore where, when untrusted user input is written to the cache
store using the `raw: true` parameter, re-reading the result from the
cache can evaluate the user input as a Marshalled object instead of
plain text. Unmarshalling of untrusted user input can have impact up
to and including RCE. At a minimum, this vulnerability allows an
attacker to inject untrusted Ruby objects into a web application.

In addition to upgrading to the latest versions of Rails,
developers should ensure that whenever they are calling
`Rails.cache.fetch` they are using consistent values of the
`raw` parameter for both reading and writing.

For Debian 8 'Jessie', these problems have been fixed in version
2:4.1.8-1+deb8u7.

We recommend that you upgrade your rails packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/06/msg00022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/rails"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8165");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-actionmailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-actionview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-activemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-activesupport-2.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-railties");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"rails", reference:"2:4.1.8-1+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-actionmailer", reference:"2:4.1.8-1+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-actionpack", reference:"2:4.1.8-1+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-actionview", reference:"2:4.1.8-1+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-activemodel", reference:"2:4.1.8-1+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-activerecord", reference:"2:4.1.8-1+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-activesupport", reference:"2:4.1.8-1+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-activesupport-2.3", reference:"2:4.1.8-1+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-rails", reference:"2:4.1.8-1+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-railties", reference:"2:4.1.8-1+deb8u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
