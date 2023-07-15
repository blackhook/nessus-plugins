#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-271.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(146524);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2020-17367", "CVE-2020-17368", "CVE-2021-26910");

  script_name(english:"openSUSE Security Update : firejail (openSUSE-2021-271)");
  script_summary(english:"Check for the openSUSE-2021-271 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for firejail fixes the following issues :

firejail 0.9.64.4 is shipped to openSUSE Leap 15.2

  - CVE-2021-26910: Fixed root privilege escalation due to
    race condition (boo#1181990)

Update to 0.9.64.4 :

  - disabled overlayfs, pending multiple fixes

  - fixed launch firefox for open url in
    telegram-desktop.profile

Update to 0.9.64.2 :

  - allow --tmpfs inside $HOME for unprivileged users

  - --disable-usertmpfs compile time option

  - allow AF_BLUETOOTH via --protocol=bluetooth

  - setup guide for new users: contrib/firejail-welcome.sh

  - implement netns in profiles

  - added nolocal6.net IPv6 network filter

  - new profiles: spectacle, chromium-browser-privacy,
    gtk-straw-viewer, gtk-youtube-viewer,
    gtk2-youtube-viewer, gtk3-youtube-viewer, straw-viewer,
    lutris, dolphin-emu, authenticator-rs, servo, npm,
    marker, yarn, lsar, unar, agetpkg, mdr, shotwell, qnapi,
    new profiles: guvcview, pkglog, kdiff3, CoyIM.

Update to version 0.9.64 :

  - replaced --nowrap option with --wrap in firemon

  - The blocking action of seccomp filters has been changed
    from killing the process to returning EPERM to the
    caller. To get the previous behaviour, use
    --seccomp-error-action=kill or syscall:kill syntax when
    constructing filters, or override in
    /etc/firejail/firejail.config file.

  - Fine-grained D-Bus sandboxing with xdg-dbus-proxy.
    xdg-dbus-proxy must be installed, if not D-Bus access
    will be allowed. With this version nodbus is deprecated,
    in favor of dbus-user none and dbus-system none and will
    be removed in a future version.

  - DHCP client support

  - firecfg only fix dektop-files if started with sudo

  - SELinux labeling support

  - custom 32-bit seccomp filter support

  - restrict $(RUNUSER) in several profiles

  - blacklist shells such as bash in several profiles

  - whitelist globbing

  - mkdir and mkfile support for /run/user directory

  - support ignore for include

  - --include on the command line

  - splitting up media players whitelists in
    whitelist-players.inc

  - new condition: HAS_NOSOUND

  - new profiles: gfeeds, firefox-x11, tvbrowser, rtv,
    clipgrab, muraster

  - new profiles: gnome-passwordsafe, bibtex, gummi, latex,
    mupdf-x11-curl

  - new profiles: pdflatex, tex, wpp, wpspdf, wps, et,
    multimc, mupdf-x11

  - new profiles: gnome-hexgl,
    com.github.johnfactotum.Foliate, mupdf-gl, mutool

  - new profiles: desktopeditors, impressive, planmaker18,
    planmaker18free

  - new profiles: presentations18, presentations18free,
    textmaker18, teams

  - new profiles: textmaker18free, xournal,
    gnome-screenshot, ripperX

  - new profiles: sound-juicer, com.github.dahenson.agenda,
    gnome-pomodoro

  - new profiles: gnome-todo, x2goclient, iagno, kmplayer,
    penguin-command

  - new profiles: frogatto, gnome-mines, gnome-nibbles,
    lightsoff, warmux

  - new profiles: ts3client_runscript.sh, ferdi, abiword,
    four-in-a-row

  - new profiles: gnome-mahjongg, gnome-robots,
    gnome-sudoku, gnome-taquin

  - new profiles: gnome-tetravex, blobwars,
    gravity-beams-and-evaporating-stars

  - new profiles: hyperrogue, jumpnbump-menu, jumpnbump,
    magicor, mindless

  - new profiles: mirrormagic, mrrescue, scorched3d-wrapper,
    scorchwentbonkers

  - new profiles: seahorse-adventures, wordwarvi, xbill,
    gnome-klotski

  - new profiles: swell-foop, fdns, five-or-more,
    steam-runtime

  - new profiles: nicotine, plv, mocp, apostrophe,
    quadrapassel, dino-im

  - new profiles: hitori, bijiben, gnote, gnubik, ZeGrapher,
    xonotic-sdl-wrapper

  - new profiles: gapplication, openarena_ded,
    element-desktop, cawbird

  - new profiles: freetube, strawberry, jitsi-meet-desktop

  - new profiles: homebank, mattermost-desktop, newsflash,
    com.gitlab.newsflash

  - new profiles: sushi, xfce4-screenshooter,
    org.gnome.NautilusPreviewer, lyx

  - new profiles: minitube, nuclear, mtpaint,
    minecraft-launcher, gnome-calendar

  - new profiles: vmware, git-cola, otter-browser, kazam,
    menulibre, musictube

  - new profiles: onboard, fractal, mirage, quaternion,
    spectral, man, psi

  - new profiles: smuxi-frontend-gnome, balsa, kube,
    trojita, youtube

  - new profiles: youtubemusic-nativefier, cola, dbus-send,
    notify-send

  - new profiles: qrencode, ytmdesktop, twitch

  - new profiles: xournalpp, chromium-freeworld, equalx

  - Make the AppArmor profile compatible with AppArmor 3.0
    (add missing include <tunables/global>)

Update to 0.9.62.4

  - fix AppArmor broken in the previous release

  - miscellaneous fixes

Update to 0.9.62.2

  - fix CVE-2020-17367

  - fix CVE-2020-17368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181990"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected firejail packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firejail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firejail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firejail-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"firejail-0.9.64.4-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"firejail-debuginfo-0.9.64.4-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"firejail-debugsource-0.9.64.4-lp152.3.6.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firejail / firejail-debuginfo / firejail-debugsource");
}
