#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2149-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134716);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2020-5267");

  script_name(english:"Debian DLA-2149-1 : rails security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In ActionView before versions 6.0.2.2 and 5.2.4.2, there is a possible
XSS vulnerability in ActionView's JavaScript literal escape helpers.
Views that use the `j` or `escape_javascript` methods may be
susceptible to XSS attacks.

For Debian 8 'Jessie', this problem has been fixed in version
2:4.1.8-1+deb8u6.

We recommend that you upgrade your rails packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/03/msg00022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/rails"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/20");
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
if (deb_check(release:"8.0", prefix:"rails", reference:"2:4.1.8-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-actionmailer", reference:"2:4.1.8-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-actionpack", reference:"2:4.1.8-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-actionview", reference:"2:4.1.8-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-activemodel", reference:"2:4.1.8-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-activerecord", reference:"2:4.1.8-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-activesupport", reference:"2:4.1.8-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-activesupport-2.3", reference:"2:4.1.8-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-rails", reference:"2:4.1.8-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-railties", reference:"2:4.1.8-1+deb8u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
