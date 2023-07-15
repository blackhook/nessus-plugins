#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1578-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118938);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-1238", "CVE-2017-15705", "CVE-2018-11780", "CVE-2018-11781");

  script_name(english:"Debian DLA-1578-1 : spamassassin security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were found in Spamassassin, which could lead
to Remote Code Execution and Denial of Service attacks under certain
circumstances.

CVE-2016-1238

Many Perl programs do not properly remove . (period) characters from
the end of the includes directory array, which might allow local users
to gain privileges via a Trojan horse module under the current working
directory.

CVE-2017-15705

A denial of service vulnerability was identified that exists in Apache
SpamAssassin before 3.4.2. The vulnerability arises with certain
unclosed tags in emails that cause markup to be handled incorrectly
leading to scan timeouts. This can cause carefully crafted emails that
might take more scan time than expected leading to a Denial of
Service.

CVE-2018-11780

A potential Remote Code Execution bug exists with the PDFInfo plugin
in Apache SpamAssassin before 3.4.2.

CVE-2018-11781

Apache SpamAssassin 3.4.2 fixes a local user code injection in the
meta rule syntax.

For Debian 8 'Jessie', these problems have been fixed in version
3.4.2-0+deb8u1. Upstream strongly advocates upgrading to the latest
upstream version so we are following that recommendation and
backported the version published as part of the 9.6 stretch release,
which also fixes many critical bugs.

We recommend that you upgrade your spamassassin packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/11/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/spamassassin"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected sa-compile, spamassassin, and spamc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sa-compile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:spamassassin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:spamc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/14");
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
if (deb_check(release:"8.0", prefix:"sa-compile", reference:"3.4.2-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"spamassassin", reference:"3.4.2-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"spamc", reference:"3.4.2-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
