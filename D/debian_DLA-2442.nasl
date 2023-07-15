#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2442-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(142667);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/20");

  script_cve_id("CVE-2019-11840");

  script_name(english:"Debian DLA-2442-1 : obfs4proxy security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"golang-go.crypto was recently updated with a fix for CVE-2019-11840.
This in turn requires all packages that use the affected code to be
recompiled in order to pick up the security fix.

CVE-2019-11840

An issue was discovered in supplementary Go cryptography libraries,
aka golang-googlecode-go-crypto. If more than 256 GiB of keystream is
generated, or if the counter otherwise grows greater than 32 bits, the
amd64 implementation will first generate incorrect output, and then
cycle back to previously generated keystream. Repeated keystream bytes
can lead to loss of confidentiality in encryption applications, or to
predictability in CSPRNG applications.

For Debian 9 stretch, this problem has been fixed in version3
0.0.7-1+deb8u1.

We recommend that you upgrade your obfs4proxy packages.

For the detailed security status of obfs4proxy please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/obfs4proxy

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/11/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/obfs4proxy"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/obfs4proxy"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected obfs4proxy package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11840");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:obfs4proxy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/10");
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
if (deb_check(release:"9.0", prefix:"obfs4proxy", reference:"0.0.7-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
