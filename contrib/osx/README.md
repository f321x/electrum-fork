Building macOS binaries
=======================

✓ _These binaries should be reproducible, meaning you should be able to generate
   binaries that match the official releases._

- _Minimum supported target system (i.e. what end-users need): macOS 12_

This guide explains how to build Electrum binaries for macOS systems.

There are two binaries, one per CPU architecture:
- `electrum-$VERSION-x86_64.dmg` for Intel Macs,
- `electrum-$VERSION-arm64.dmg` for Apple silicon Macs.

Both are built on an x86_64 macOS, in one build environment: Python, the C extensions and
the native libraries are universal2 (x86_64 + arm64) binaries, and PyInstaller thins each
app to one architecture.


## Building the binary

### 1. The builder VM

The release binaries are built in an x86_64 macOS 15 (Sequoia) VM, using
[OSX-KVM](https://github.com/kholia/OSX-KVM) on a Linux host. The guest must have:
- macOS 15 (Sequoia), 15.3 or later (the Command Line Tools 16.4 need it). Turn off automatic
  updates.
- The Xcode Command Line Tools 16.4 (`CLTools_Executables` 16.4.0.0.1.1747106510),
  not the full Xcode. 16.4 is the newest version Apple offers for macOS 15.
- No Homebrew or MacPorts. In particular, `/usr/local/include` and `/usr/local/lib`
  must be empty or absent, as clang searches them.
- A user named `vagrant`, with `electrum` cloned directly into its home dir:
  `/Users/vagrant/electrum`. The path ends up in the binaries.

The output should not depend on the host's CPU model or the amount of RAM.

Host requirements:
- A CPU with VT-x/AMD-V, and AVX2, BMI1, BMI2, FMA, MOVBE and LZCNT (Intel Haswell or newer,
  AMD Zen or newer). On Linux, this must list all six:
  `grep -o -w -e avx2 -e bmi1 -e bmi2 -e fma -e movbe -e abm /proc/cpuinfo | sort -u`
- The guest needs 4 GB of RAM, 2 or 4 vCPUs (4 build faster) and a 64 GB disk (sparse qcow2).
  A build needs about 6 GB of disk space, including the Command Line Tools.

Notes on OSX-KVM:
- Choose the QEMU CPU model by the host CPU, and never use `-cpu host`:
  - Intel Skylake or newer, and AMD: `-cpu Skylake-Client-v4,vendor=GenuineIntel,+invtsc,vmware-cpuid-freq=on`
  - Intel Haswell: `-cpu Haswell-noTSX,stepping=3,vendor=GenuineIntel,+invtsc,vmware-cpuid-freq=on`
    (without `stepping=3`, macOS panics: "Haswell pre-C0 steppings are not supported")
  - Intel Broadwell: `-cpu Broadwell-noTSX,vendor=GenuineIntel,+invtsc,vmware-cpuid-freq=on`
- Use `-smp 4,sockets=1,cores=4,threads=1` (or `-smp 2,sockets=1,cores=2,threads=1`). On AMD
  hosts, the host's clocksource must be `tsc`
  (`/sys/devices/system/clocksource/clocksource0/current_clocksource`).
- Bind the SSH port forward and VNC to localhost, e.g. `hostfwd=tcp:127.0.0.1:2222-:22`.
- Fetch the installer with `./fetch-macOS-v2.py` and choose Sequoia.
- In Setup Assistant, skip the Apple ID, and create the `vagrant` user.
- Enable SSH (System Settings > General > Sharing > Remote Login), and build over SSH.
- Keep copies of the macOS installer and the Command Line Tools pkg: Apple removes old
  versions from its servers.

Install the Command Line Tools in the guest:

    touch /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress
    softwareupdate --list        # note the "Label:" of "Command Line Tools for Xcode 16.4"
    sudo softwareupdate --install "<that label>"
    rm /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress


### 2. Build Electrum

    cd ~
    git clone https://github.com/spesmilo/electrum.git
    cd electrum
    git checkout "$VERSION"  # the tag to build
    ./contrib/osx/make_osx.sh

It asks for your password once, to install Python from python.org. The script downloads its
build tools (GNU autotools, cmake) and keeps them in `contrib/osx/.cache`, so later
builds are faster. It runs in a clean environment.

The results are in `dist/`:
- `x86_64/Electrum.app` and `electrum-$VERSION-x86_64-unsigned.dmg`,
- `arm64/Electrum.app` and `electrum-$VERSION-arm64-unsigned.dmg`.

At the end, the script prints a hash of each app. It should be the same for every builder.


### 3. For release binaries, here be dragons

If you want the binaries codesigned for macOS and notarised by Apple's central server,
also run the `sign_osx.sh` script:

    CODESIGN_CERT="Developer ID Application: Electrum Technologies GmbH (L6P37P7P56)" \
    APPLE_TEAM_ID="L6P37P7P56" \
    APPLE_ID_USER="me@email.com" \
    APPLE_ID_PASSWORD="1234" \
    ./contrib/osx/sign_osx.sh

(note: `APPLE_ID_PASSWORD` is an app-specific password, *not* the account password)

This signs and notarizes both apps, and creates `dist/electrum-$VERSION-x86_64.dmg` and
`dist/electrum-$VERSION-arm64.dmg`.

Sign in the builder VM: `compare_dmg` expects the signature layout of its codesign.


## Verifying reproducibility and comparing against official binary

Every user can verify that the official binaries were created from the source code in this
repository.

1. Build your own binaries as described above.
2. Use the provided `compare_dmg` script to compare each DMG you built with the official
   release DMG of the same architecture:
    ```
    $ ./contrib/osx/compare_dmg dist/electrum-$VERSION-x86_64-unsigned.dmg electrum-$VERSION-x86_64.dmg
    $ ./contrib/osx/compare_dmg dist/electrum-$VERSION-arm64-unsigned.dmg electrum-$VERSION-arm64.dmg
    ```
   The official app is codesigned and notarized, so `compare_dmg` first copies its code
   signatures and notarization ticket onto a copy of your app (`codesign_replay.py`). Then it
   compares all files, directories and symlinks of the two apps.
   (We cannot compare the `.dmg` files directly: `hdiutil`'s output is not deterministic,
   and they contain codesigned files.)


## FAQ

### What is macOS "codesigning" and "notarization"?

Codesigning is the macOS OS-native signing of executables/shared-libs,
that needs to be done using an ~x509-like certificate that chains back to Apple's root CA.
Once a developer certificate is obtained from Apple, it can be used to codesign locally
on a dev machine.

Notarization is a further step usually done after, which entails uploading a distributable
over the network to the Apple mothership central server, which runs some arbitrary checks on it,
and if it finds the file ok, the central server gives the dev a notarization staple.
This staple can then be optionally "attached" to the distributable, mutating it, which we do.
(If the staple is not attached, enduser machines request it from the mothership at runtime.)

Both these steps should be done during the build process.

### What is "codesigned" and/or "notarized", re the official release?

For each architecture:
- `make_osx.sh` builds a `.app`, which is unsigned/unnotarized
  (PyInstaller signs its binaries ad hoc, i.e. without a certificate)
  - at this point, this `.app` is "byte-for-byte" reproducible
    - this is the sanity-check hash printed at the end of `make_osx.sh`
  - `make_osx.sh` creates a `.dmg` from the `.app`
    - this `.dmg` is not used for the official release at all, but used as the basis of
      testing reproducibility using the `compare_dmg` script
- `sign_osx.sh` codesigns the `.app` (mutating it)
- `sign_osx.sh` -> `notarize_app.sh` notarizes the `.app` (mutating it)
- `sign_osx.sh` creates a `.dmg` from the `.app`
- `sign_osx.sh` codesigns the `.dmg` (mutating it)
  - this `.dmg` becomes the official release distributable

That is, the official release `.dmg` is codesigned but NOT notarized.
It contains a `.app`, which is codesigned AND notarized.

### How to check if a file is codesigned?

Both the `.dmg` and the contained `.app` are codesigned:
```
$ codesign --verify --deep --strict --verbose=2 $HOME/Desktop/electrum-4.5.8.dmg && echo "signed"
/Users/vagrant/Desktop/electrum-4.5.8.dmg: valid on disk
/Users/vagrant/Desktop/electrum-4.5.8.dmg: satisfies its Designated Requirement
signed
```
```
$ codesign --verify --deep --strict --verbose=1 $HOME/Desktop/Electrum-4.5.8.app && echo "signed"
/Users/vagrant/Desktop/Electrum-4.5.8.app: valid on disk
/Users/vagrant/Desktop/Electrum-4.5.8.app: satisfies its Designated Requirement
signed
```

Also see `$ codesign -dvvv $HOME/Desktop/electrum-4.5.8.dmg`

### How to check if a file is notarized?

The outer `.dmg` is NOT notarized, but the inner `.app` is notarized:
```
$ spctl -a -vvv -t install $HOME/Desktop/electrum-4.5.8.dmg
/Users/vagrant/Desktop/electrum-4.5.8.dmg: rejected
source=Unnotarized Developer ID
origin=Developer ID Application: Electrum Technologies GmbH (L6P37P7P56)
```
```
$ spctl -a -vvv -t install $HOME/Desktop/Electrum-4.5.8.app
/Users/vagrant/Desktop/Electrum-4.5.8.app: accepted
source=Notarized Developer ID
origin=Developer ID Application: Electrum Technologies GmbH (L6P37P7P56)
```

### How to simulate the signing procedure?

It is possible to run `sign_osx.sh` using a self-signed certificate to test the
signing procedure without using a production certificate.

Note that the notarization process will be skipped as it is not possible to notarize
an executable with Apple using a self-signed certificate.

#### To generate a self-signed certificate, inside your **MacOS VM**:

1. Open the `Keychain Access` application.
2. In the menubar go to `Keychain Access` > `Certificate Assistant` > `Create a Certificate...`
3. Set a name (e.g. `signing_dummy`)
4. Change `Certificate Type` to *'Code Signing'*
5. Click `Create` and `Continue`.

You now have a self-signed certificate `signing_dummy` added to your `login` keychain.

#### Fix "Access Control" settings for private key (of new cert)

If you try using your cert with `codesign`, it will fail:
```
% cp -f /bin/ls ./CODESIGN_TEST
% set +e
% codesign -s "signing_dummy" --dryrun -f ./CODESIGN_TEST
./CODESIGN_TEST: replacing existing signature
./CODESIGN_TEST: errSecInternalComponent
```

To fix this, find the corresponding private key (for the cert) also named `signing_dummy`,
in `Keychain Access`.
- Right-click the private key item > `Get Info` > `Access Control`.
- There is a list of allowed apps in the popup that can access the private key.
- Click the small `+` (plus) icon. Then press `Win`+`Shift`+`G`: go to folder: `/usr/bin/codesign`,
  and add the codesign executable to the list.
- Click `Save Changes`.

Now try again:
```
% security unlock-keychain login.keychain
% codesign -s "signing_dummy" --dryrun -f ./CODESIGN_TEST
./CODESIGN_TEST: replacing existing signature
```

#### To sign the executables with the self-signed certificate:

Assuming you have the outputs of `make_osx.sh` inside `~/electrum/dist`.

In `~/electrum` run:

`$ CODESIGN_CERT="signing_dummy" ./contrib/osx/sign_osx.sh`

After `sign_osx.sh` finished, you will have two new `*.dmg` files inside `electrum/dist`
(without the `-unsigned` postfix), signed with your certificate.

#### To compare the unsigned executable with the self-signed executable:

`$ ./contrib/osx/compare_dmg <unsigned dmg> <self-signed dmg>` should succeed, for each architecture.


### Historical issues codesigning with production cert

#### "Trust" settings of developer certificate must be set to "Use System Defaults"

Fiddling with the trust settings of the cert produces all kinds of obscure results/errors.

Error1:
```
% export CODESIGN_CERT="Developer ID Application: Electrum Technologies GmbH (L6P37P7P56)"
% cp -f /bin/ls ./CODESIGN_TEST
% codesign -s "$CODESIGN_CERT" -f ./CODESIGN_TEST
./CODESIGN_TEST: replacing existing signature
Warning: unable to build chain to self-signed root for signer "Developer ID Application: Electrum Technologies GmbH (L6P37P7P56)"
./CODESIGN_TEST: errSecInternalComponent
```

We saw error1 when multiple use-cases had trust settings set to "Always Trust".


Error2:
```
% export CODESIGN_CERT="Developer ID Application: Electrum Technologies GmbH (L6P37P7P56)"
% cp -f /bin/ls ./CODESIGN_TEST
% codesign -s "$CODESIGN_CERT" -f --timestamp CODESIGN_TEST
CODESIGN_TEST: replacing existing signature
% codesign --verify --strict --verbose=2 CODESIGN_TEST
CODESIGN_TEST: valid on disk
CODESIGN_TEST: does not satisfy its designated Requirement
```

We saw error2 when only "Code Signing" was set to "Always Trust".


Solution:
- Open the `Keychain Access` application.
- Right-click the certificate item > `Get Info`.
- Open the `Trust` dropdown.
- Set: "When using this certificate" to "Use System Defaults"

Note: cannot reproduce issue using self-signed "signing_dummy" cert, only using prod cert.
