#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2330-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139628);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2017-17742", "CVE-2019-16201", "CVE-2019-16254", "CVE-2019-16255", "CVE-2019-8320", "CVE-2019-8321", "CVE-2019-8322", "CVE-2019-8323", "CVE-2019-8324", "CVE-2019-8325");

  script_name(english:"Debian DLA-2330-1 : jruby security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were fixed in JRuby, a 100% pure-Java
implementation of Ruby.

CVE-2017-17742 CVE-2019-16254

HTTP Response Splitting attacks in the HTTP server of WEBrick.

CVE-2019-16201

Regular Expression Denial of Service vulnerability of WEBrick's Digest
access authentication.

CVE-2019-8320

Delete directory using symlink when decompressing tar.

CVE-2019-8321

Escape sequence injection vulnerability in verbose.

CVE-2019-8322

Escape sequence injection vulnerability in gem owner.

CVE-2019-8323

Escape sequence injection vulnerability in API response handling.

CVE-2019-8324

Installing a malicious gem may lead to arbitrary code execution.

CVE-2019-8325

Escape sequence injection vulnerability in errors.

CVE-2019-16255

Code injection vulnerability of Shell#[] and Shell#test.

For Debian 9 stretch, these problems have been fixed in version
1.7.26-1+deb9u2.

We recommend that you upgrade your jruby packages.

For the detailed security status of jruby please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/jruby

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00027.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/jruby"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/jruby"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected jruby package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8320");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jruby");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"jruby", reference:"1.7.26-1+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
