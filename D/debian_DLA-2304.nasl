#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2304-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139247);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/06");

  script_cve_id("CVE-2015-9542");

  script_name(english:"Debian DLA-2304-1 : libpam-radius-auth security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"`add_password` in pam_radius_auth.c in pam_radius 1.4.0 does not
correctly check the length of the input password, and is vulnerable to
a stack-based buffer overflow during memcpy(). An attacker could send
a crafted password to an application (loading the pam_radius library)
and crash it. Arbitrary code execution might be possible, depending on
the application, C library, compiler, and other factors.

For Debian 9 stretch, this problem has been fixed in version
1.3.16-5+deb9u1.

We recommend that you upgrade your libpam-radius-auth packages.

For the detailed security status of libpam-radius-auth please refer to
its security tracker page at:
https://security-tracker.debian.org/tracker/libpam-radius-auth

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libpam-radius-auth"
  );
  # https://security-tracker.debian.org/tracker/source-package/libpam-radius-auth
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae15fc5f"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected libpam-radius-auth package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-radius-auth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libpam-radius-auth", reference:"1.3.16-5+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
