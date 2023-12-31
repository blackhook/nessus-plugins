#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-264-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84495);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-3406", "CVE-2015-3407", "CVE-2015-3408", "CVE-2015-3409");
  script_bugtraq_id(73935, 73937);

  script_name(english:"Debian DLA-264-1 : libmodule-signature-perl security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"John Lightsey discovered multiple vulnerabilities in
Module::Signature, a Perl module to manipulate CPAN SIGNATURE files.
The Common Vulnerabilities and Exposures project identifies the
following problems :

CVE-2015-3406

Module::Signature could parse the unsigned portion of the SIGNATURE
file as the signed portion due to incorrect handling of PGP signature
boundaries.

CVE-2015-3407

Module::Signature incorrectly handled files that are not listed in the
SIGNATURE file. This includes some files in the t/ directory that
would execute when tests are run.

CVE-2015-3408

Module::Signature used two argument open() calls to read the files
when generating checksums from the signed manifest. This allowed to
embed arbitrary shell commands into the SIGNATURE file that would be
executed during the signature verification process.

CVE-2015-3409

Module::Signature incorrectly handled module loading, allowing to load
modules from relative paths in @INC. A remote attacker providing a
malicious module could use this issue to execute arbitrary code during
signature verification.

For the squeeze distribution, these issues have been fixed in version
0.63-1+squeeze2 of libmodule-signature-perl. Please note that the
libtest-signature-perl package was also updated for compatibility with
the CVE-2015-3407 fix.

We recommend that you upgrade your libmodule-signature-perl and
libtest-signature-perl packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/07/msg00001.html"
  );
  # https://packages.debian.org/source/squeeze-lts/libmodule-signature-perl
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?84a28e43"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected libmodule-signature-perl package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmodule-signature-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"6.0", prefix:"libmodule-signature-perl", reference:"0.63-1+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
