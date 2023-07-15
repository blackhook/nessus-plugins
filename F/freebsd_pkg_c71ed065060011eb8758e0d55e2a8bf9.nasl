#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2020 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include("compat.inc");

if (description)
{
  script_id(141149);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/23");

  script_cve_id("CVE-2020-26164");

  script_name(english:"FreeBSD : kdeconnect -- packet manipulation can be exploited in a Denial of Service attack (c71ed065-0600-11eb-8758-e0d55e2a8bf9)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Albert Astals Cid reports : KDE Project Security AdvisoryTitleKDE
Connect: packet manipulation can be exploited in a Denial of Service
attackRisk RatingImportantCVECVE-2020-26164Versionskdeconnect <=
20.08.1AuthorAlbert Vaca Cintora <albertvaka@gmail.com>Date2 October
2020Overview

An attacker on your local network could send maliciously crafted
packets to other hosts running kdeconnect on the network, causing them
to use large amounts of CPU, memory or network connections, which
could be used in a Denial of Service attack within the network.

Impact

Computers that run kdeconnect are susceptible to DoS attacks from the
local network.

Workaround

We advise you to stop KDE Connect when on untrusted networks like
those on airports or conferences.

Since kdeconnect is dbus activated it is relatively hard to make sure
it stays stopped so the brute force approach is to uninstall the
kdeconnect package from your system and then run

kquitapp5 kdeconnectd

Just install the package again once you're back in a trusted network.

Solution

KDE Connect 20.08.2 patches several code paths that could result in a
DoS.

You can apply these patches on top of 20.08.1 :

-
https://invent.kde.org/network/kdeconnect-kde/-/commit/f183b5447bad476
55c21af87214579f03bf3a163

-
https://invent.kde.org/network/kdeconnect-kde/-/commit/b279c52101d3f7c
c30a26086d58de0b5f1c547fa

-
https://invent.kde.org/network/kdeconnect-kde/-/commit/d35b88c1b25fe13
715f9170f18674d476ca9acdc

-
https://invent.kde.org/network/kdeconnect-kde/-/commit/b496e66899e5bc9
547b6537a7f44ab44dd0aaf38

-
https://invent.kde.org/network/kdeconnect-kde/-/commit/5310eae85dbdf92
fba30375238a2481f2e34943e

-
https://invent.kde.org/network/kdeconnect-kde/-/commit/721ba9faafb79aa
c73973410ee1dd3624ded97a5

-
https://invent.kde.org/network/kdeconnect-kde/-/commit/ae58b9dec49c809
b85b5404cee17946116f8a706

-
https://invent.kde.org/network/kdeconnect-kde/-/commit/66c768aa9e7fba3
0b119c8b801efd49ed1270b0a

-
https://invent.kde.org/network/kdeconnect-kde/-/commit/85b691e40f525e2
2ca5cc4ebe79c361d71d7dc05

-
https://invent.kde.org/network/kdeconnect-kde/-/commit/48180b46552d407
29a36b7431e97bbe2b5379306

Credits

Thanks Matthias Gerstner and the openSUSE security team for reporting
the issue.

Thanks to Aleix Pol, Nicolas Fella and Albert Vaca Cintora for the
patches."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kde.org/info/security/advisory-20201002-1.txt"
  );
  # https://vuxml.freebsd.org/freebsd/c71ed065-0600-11eb-8758-e0d55e2a8bf9.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d951166"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:kdeconnect-kde");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"kdeconnect-kde<=20.08.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
