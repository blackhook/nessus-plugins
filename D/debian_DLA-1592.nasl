#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1592-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119120);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-19141", "CVE-2018-19143");

  script_name(english:"Debian DLA-1592-1 : otrs2 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two security vulnerabilities were discovered in OTRS, a Ticket Request
System, that may lead to privilege escalation or arbitrary file write.

CVE-2018-19141

An attacker who is logged into OTRS as an admin user may manipulate
the URL to cause execution of JavaScript in the context of OTRS.

CVE-2018-19143

An attacker who is logged into OTRS as a user may manipulate the
submission form to cause deletion of arbitrary files that the OTRS web
server user has write access to.

Please also read the upstream advisory for CVE-2018-19141. If you
think you might be affected then you should consider to run the
mentioned clean-up SQL statements to remove possible affected records.

https://community.otrs.com/security-advisory-2018-09-security-update-f
or-otrs-framework/

For Debian 8 'Jessie', these problems have been fixed in version
3.3.18-1+deb8u7.

We recommend that you upgrade your otrs2 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  # https://community.otrs.com/security-advisory-2018-09-security-update-for-otrs-framework/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c3b34ef"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/11/msg00028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/otrs2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected otrs, and otrs2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:otrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:otrs2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"otrs", reference:"3.3.18-1+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"otrs2", reference:"3.3.18-1+deb8u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
