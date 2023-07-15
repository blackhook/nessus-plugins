#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2553-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(146360);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id("CVE-2019-5086", "CVE-2019-5087");

  script_name(english:"Debian DLA-2553-2 : xcftools regression update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The patch to address CVE-2019-5086 and CVE-2019-5087 was not portable
and did not work on 32 bit processor architectures. This update fixes
the problem. For reference, the original advisory text follows.

Claudio Bozzato of Cisco Talos discovered an exploitable integer
overflow vulnerability in the flattenIncrementally function in the
xcf2png and xcf2pnm binaries of xcftools. An integer overflow can
occur while walking through tiles that could be exploited to corrupt
memory and execute arbitrary code. In order to trigger this
vulnerability, a victim would need to open a specially crafted XCF
file.

For Debian 9 stretch, this problem has been fixed in version
1.0.7-6+deb9u2.

We recommend that you upgrade your xcftools packages.

For the detailed security status of xcftools please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/xcftools

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/03/msg00008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/xcftools"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/xcftools"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected xcftools package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xcftools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"xcftools", reference:"1.0.7-6+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
