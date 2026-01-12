from pathlib import Path

def after_apk_build(toolchain):
    """
    Injects custom activities into AndroidManifest.xml before the APK is compiled.
    """
    print("Running custom manifest hook...")

    # Locate the AndroidManifest.xml in the distribution folder
    # The path is usually: .buildozer/android/platform/build-.../dists/{appname}/src/main/AndroidManifest.xml
    dist_dir = Path(toolchain.dist_dir)
    manifest_path = dist_dir / "src" / "main" / "AndroidManifest.xml"

    if not manifest_path.exists():
        print(f"Error: Manifest not found at {manifest_path}")
        return

    # The XML content you want to inject
    extra_xml = """
    <activity android:name="org.electrum.biometry.BiometricActivity"
              android:exported="false"
    """

    # Read the current manifest
    manifest_content = manifest_path.read_text(encoding="utf-8")

    # Inject the extra XML before the closing </application> tag
    if "org.electrum.biometry.BiometricActivity" not in manifest_content:
        new_manifest = manifest_content.replace("</application>", f"{extra_xml}\n</application>")
        manifest_path.write_text(new_manifest, encoding="utf-8")
        print("Successfully injected BiometricActivity into AndroidManifest.xml")
    else:
        print("BiometricActivity already present in manifest, skipping injection.")
