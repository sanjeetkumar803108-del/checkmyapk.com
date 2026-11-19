export type BlogCategory =
  | 'Android APK'
  | 'Web & API'
  | 'Cloud & BaaS'
  | 'Play Store Compliance';

export interface BlogSection {
  heading: string;
  body: string[];
  bullets?: string[];
}

export interface BlogCodeDiff {
  filename: string;
  language: string;
  before: string;
  after: string;
  verifyCommand: string;
}

export interface BlogFaq {
  q: string;
  a: string;
}

export interface BlogPost {
  slug: string;
  title: string;
  metaTitle: string;
  metaDescription: string;
  category: BlogCategory;
  owaspRef: string;
  publishedAt: string;
  readTime: string;
  keywords: string[];
  excerpt: string;
  summaryPoints: string[];
  sections: BlogSection[];
  codeDiff: BlogCodeDiff;
  faqs: BlogFaq[];
}

export const APK_BLOG_POSTS: BlogPost[] = [
  {
    slug: 'check-android-apk-for-leaked-api-keys',
    title: 'How to Check an Android APK for Leaked API Keys & Hardcoded Secrets',
    metaTitle: 'How to Check an Android APK for Leaked API Keys | CheckMyAPK',
    metaDescription:
      'Learn how attackers extract hardcoded OpenAI, Stripe, AWS, and Firebase keys from classes.dex and resources.arsc—and how to audit your APK in seconds.',
    category: 'Android APK',
    owaspRef: 'MASVS-CRYPTO-1',
    publishedAt: '2026-11-18',
    readTime: '6 min read',
    keywords: [
      'check apk for api keys',
      'apk secret scanner',
      'android hardcoded secrets',
      'decompile apk secrets',
      'classes.dex api key leak',
    ],
    excerpt:
      'Every compiled Android APK is a ZIP archive whose Dalvik bytecode and XML resources can be decompiled in seconds. Here is how secret leaks happen and how to eliminate them permanently.',
    summaryPoints: [
      'Attackers run JADX-GUI or strings on classes.dex and assets/ to harvest API keys in under 15 seconds.',
      'BuildConfig fields and res/values/strings.xml are stored in plaintext inside compiled APKs—they are not secure vaults.',
      'Move private AI, payment, and database secrets behind an authenticated backend proxy and verify with automated DEX scanning.',
    ],
    sections: [
      {
        heading: 'Why Hardcoded Keys in APKs Are Trivial to Steal',
        body: [
          'Many developers assume that compiling Kotlin, Java, Flutter, or React Native into a release APK hides their API keys. In reality, an APK is simply a standard ZIP container holding Dalvik bytecode (classes.dex), compiled resources (resources.arsc), and web/JS assets.',
          'Automated scraper bots continuously download newly published APKs from third-party mirrors and run regex signature scans for OpenAI (sk-proj-...), Stripe (sk_live_...), AWS (AKIA...), MongoDB URIs, and unrestricted Google Cloud keys (AIza...).',
        ],
        bullets: [
          'BuildConfig.API_KEY compiles directly into the DEX constant string pool.',
          'Capacitor, Cordova, and React Native apps bundle plain JS files inside assets/public/ or index.android.bundle.',
          'Even ProGuard/R8 obfuscation renames classes and methods—it does not encrypt literal string constants.',
        ],
      },
      {
        heading: 'Real-World Attack Scenario',
        body: [
          'An attacker downloads your production APK, opens it in JADX-GUI, and searches for "Bearer", "AIza", or "sk_live". Within seconds they copy your OpenAI or Stripe key and trigger thousands of dollars in fraudulent API calls or exfiltrate private customer records.',
        ],
      },
      {
        heading: 'The Production-Safe Architecture',
        body: [
          'Never ship privileged third-party credentials inside a mobile binary. Instead, authenticate the mobile client with a short-lived user session (JWT or Firebase Auth ID token) and route sensitive API requests through your own backend server where secrets live in environment variables.',
        ],
      },
    ],
    codeDiff: {
      filename: 'ApiClient.kt (Backend Proxy Pattern)',
      language: 'kotlin',
      before: `// VULNERABLE: Raw secret compiled directly into classes.dex
val request = Request.Builder()
    .url("https://api.openai.com/v1/chat/completions")
    .addHeader("Authorization", "Bearer sk-proj-9x8a7b6c5d4e...")
    .build()`,
      after: `// SECURE: Call your own authenticated backend proxy (secret stays on server)
val request = Request.Builder()
    .url("https://api.yourdomain.com/v1/ai/chat")
    .addHeader("Authorization", "Bearer \${userSessionJwt}")
    .build()`,
      verifyCommand: 'Upload your release .apk to CheckMyAPK.com -> Verify 0 Secret Findings in DEX & Assets',
    },
    faqs: [
      {
        q: 'Does ProGuard or R8 hide hardcoded API keys in an APK?',
        a: 'No. ProGuard/R8 shrinks and renames class and method identifiers, but string literals in the DEX string pool remain readable in plaintext.',
      },
      {
        q: 'Is storing an API key in local.properties and BuildConfig safe?',
        a: 'It keeps the key out of Git, which is good, but Gradle still embeds the BuildConfig string directly inside the compiled APK.',
      },
    ],
  },
  {
    slug: 'fix-android-uses-cleartext-traffic-true',
    title: 'How to Fix android:usesCleartextTraffic="true" in Android & Capacitor Apps',
    metaTitle: 'Fix android:usesCleartextTraffic="true" in Android & Capacitor | CheckMyAPK',
    metaDescription:
      'Step-by-step guide to disabling cleartext HTTP traffic in AndroidManifest.xml, network_security_config.xml, and Capacitor config to prevent MitM attacks.',
    category: 'Android APK',
    owaspRef: 'MASVS-NETWORK-1',
    publishedAt: '2026-11-16',
    readTime: '5 min read',
    keywords: [
      'android usesCleartextTraffic true fix',
      'capacitor cleartext false',
      'network_security_config.xml https',
      'android mitm protection',
    ],
    excerpt:
      'Enabling usesCleartextTraffic="true" silently disables Android platform HTTPS enforcement across your app and third-party SDKs. Learn how to lock it down cleanly.',
    summaryPoints: [
      'android:usesCleartextTraffic="true" permits unencrypted HTTP connections vulnerable to public Wi-Fi Man-in-the-Middle attacks.',
      'In Capacitor apps, setting server.cleartext: true causes npx cap sync to inject usesCleartextTraffic="true" into the merged manifest.',
      'Pair android:usesCleartextTraffic="false" with a strict res/xml/network_security_config.xml file.',
    ],
    sections: [
      {
        heading: 'Why Cleartext Traffic Still Appears in Modern APKs',
        body: [
          'Android 9 (API 28) disabled cleartext HTTP by default, yet many production APKs still ship with android:usesCleartextTraffic="true". The most common cause is a leftover local development setting in AndroidManifest.xml or capacitor.config.ts that was never reverted before building the release APK.',
        ],
      },
      {
        heading: 'Attack Vector: Public Wi-Fi Interception & Script Injection',
        body: [
          'When cleartext HTTP is allowed, any attacker on a shared coffee-shop Wi-Fi network or rogue access point can sniff session cookies, authorization headers, and API JSON responses—or inject malicious JavaScript directly into hybrid WebView traffic.',
        ],
      },
      {
        heading: 'Fixing Both Native Android and Capacitor Builds',
        body: [
          'Remove android:usesCleartextTraffic="true" from AndroidManifest.xml and explicitly set it to "false". If you use Capacitor, ensure server.cleartext is false and androidScheme is "https" in capacitor.config.ts, then run npx cap sync android before generating your release build.',
        ],
      },
    ],
    codeDiff: {
      filename: 'AndroidManifest.xml & res/xml/network_security_config.xml',
      language: 'xml',
      before: `<application
    android:usesCleartextTraffic="true"
    android:allowBackup="true">`,
      after: `<application
    android:usesCleartextTraffic="false"
    android:networkSecurityConfig="@xml/network_security_config"
    android:allowBackup="false">

<!-- res/xml/network_security_config.xml -->
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors>
      <certificates src="system" />
    </trust-anchors>
  </base-config>
</network-security-config>`,
      verifyCommand: 'npx cap sync android && ./gradlew assembleRelease',
    },
    faqs: [
      {
        q: 'How can I allow HTTP only for localhost during development?',
        a: 'Put a separate AndroidManifest.xml inside src/debug/ with cleartext overrides, or use <debug-overrides> inside network_security_config.xml so production builds remain strictly HTTPS.',
      },
      {
        q: 'Does Google Play flag usesCleartextTraffic="true"?',
        a: 'Yes, security reviews and Play Data Safety declarations expect encrypted transit; cleartext traffic increases the risk of policy warnings and failed enterprise security audits.',
      },
    ],
  },
  {
    slug: 'fix-unprotected-exported-components-android',
    title: 'Unprotected android:exported="true" Components in Android 12+: Risks & Fixes',
    metaTitle: 'Fix Unprotected android:exported="true" in AndroidManifest.xml | CheckMyAPK',
    metaDescription:
      'Prevent Intent hijacking and unauthorized IPC access by auditing exported Activities, Services, BroadcastReceivers, and ContentProviders in Android.',
    category: 'Android APK',
    owaspRef: 'MASVS-PLATFORM-1',
    publishedAt: '2026-11-14',
    readTime: '6 min read',
    keywords: [
      'android exported true vulnerability',
      'unprotected exported activity',
      'android ipc security',
      'intent redirection android fix',
    ],
    excerpt:
      'Every component with android:exported="true" and no permission guard is a public entry point callable by any malicious app installed on the user device.',
    summaryPoints: [
      'Non-launcher Activities, Services, BroadcastReceivers, and ContentProviders should default to android:exported="false".',
      'Adding an <intent-filter> without careful review often leads developers to blindly flip android:exported="true" to satisfy Android 12+ build errors.',
      'Protect legitimately shared components with a signature-level android:permission and validate every incoming Intent extra.',
    ],
    sections: [
      {
        heading: 'How Android 12+ Exported Errors Create Security Holes',
        body: [
          'Since Android 12 (API 31), apps must explicitly declare android:exported on any component containing an <intent-filter>. Under deadline pressure, many teams blindly add android:exported="true" to internal Activities, sync Services, or push Receivers just to make Gradle compile.',
        ],
      },
      {
        heading: 'What an Attacker Can Do via Exported IPC',
        body: [
          'A malicious app installed on the same Android device can craft explicit Intents to bypass your login screen, launch internal WebView activities with attacker-controlled URLs, trigger background sync services, or query unprotected ContentProviders for local SQLite data.',
        ],
        bullets: [
          'Exported WebView Activity + unvalidated URL extra = JavaScript injection & token theft.',
          'Exported ContentProvider without readPermission = full local database dump via adb or rogue app.',
          'Exported BroadcastReceiver = spoofing internal app state transitions.',
        ],
      },
      {
        heading: 'Hardening Your IPC Surface',
        body: [
          'Audit every component in your merged AndroidManifest.xml. Only your MAIN/LAUNCHER Activity and verified App Link handlers should be exported publicly. Everything else should be android:exported="false" or guarded by a custom signature-level permission.',
        ],
      },
    ],
    codeDiff: {
      filename: 'AndroidManifest.xml',
      language: 'xml',
      before: `<activity
    android:name=".ui.InternalWebViewActivity"
    android:exported="true" />
<service
    android:name=".sync.TokenSyncService"
    android:exported="true" />`,
      after: `<activity
    android:name=".ui.InternalWebViewActivity"
    android:exported="false" />
<service
    android:name=".sync.TokenSyncService"
    android:exported="false" />

<!-- If another of YOUR apps needs access, enforce signature-level permission -->
<permission
    android:name="\${applicationId}.permission.INTERNAL_IPC"
    android:protectionLevel="signature" />`,
      verifyCommand: 'adb shell am start -n com.yourapp.id/.ui.InternalWebViewActivity # Should return SecurityException',
    },
    faqs: [
      {
        q: 'Should my MainActivity have android:exported="true"?',
        a: 'Yes. The launcher Activity with ACTION_MAIN and CATEGORY_LAUNCHER must be exported="true" so the Android OS launcher can open your app.',
      },
      {
        q: 'Can third-party SDKs add exported components to my APK?',
        a: 'Yes. Libraries merge their own manifests into your final APK. Always audit the compiled APK (e.g. via CheckMyAPK APK Internals tab) rather than only checking your source manifest.',
      },
    ],
  },
  {
    slug: 'enable-proguard-r8-obfuscation-android-apk',
    title: 'How to Enable ProGuard / R8 Obfuscation & Verify Your Release APK',
    metaTitle: 'Enable ProGuard / R8 Obfuscation in Android Gradle | CheckMyAPK',
    metaDescription:
      'Protect your Android business logic from instant JADX reverse engineering by configuring R8 minifyEnabled, shrinkResources, and keep rules properly.',
    category: 'Android APK',
    owaspRef: 'MASVS-RESILIENCE-1',
    publishedAt: '2026-11-11',
    readTime: '5 min read',
    keywords: [
      'proguard r8 obfuscation android',
      'minifyEnabled true gradle',
      'check apk obfuscation',
      'prevent apk reverse engineering',
    ],
    excerpt:
      'Without R8 minification, your entire Kotlin/Java class hierarchy, billing checks, and API models can be read like original source code inside JADX-GUI.',
    summaryPoints: [
      'Enabling minifyEnabled true and shrinkResources true shrinks APK size by 20-40% while scrambling internal class and method names.',
      'Always keep your mapping.txt file and upload it to Google Play Console / Crashlytics for readable stack traces.',
      'Verify obfuscation on the final compiled .apk—not just build.gradle—to confirm R8 actually ran on your release variant.',
    ],
    sections: [
      {
        heading: 'What Unobfuscated APKs Expose to Reverse Engineers',
        body: [
          'When minifyEnabled is false, every package name, method signature (e.g. isPremiumSubscriber(), verifyLicense()), and internal data model is preserved verbatim inside classes.dex. Attackers can locate subscription checks in seconds and patch them using apktool or Frida.',
        ],
      },
      {
        heading: 'Enabling R8 Full Mode Safely',
        body: [
          'Modern Android Gradle Plugin (AGP 8+) uses R8 by default. Turn on minifyEnabled true and shrinkResources true inside buildTypes.release, and add targeted @Keep annotations or proguard-rules.pro entries only for Retrofit/Gson/Room serialization models.',
        ],
      },
    ],
    codeDiff: {
      filename: 'android/app/build.gradle',
      language: 'groovy',
      before: `buildTypes {
  release {
    minifyEnabled false
    shrinkResources false
  }
}`,
      after: `buildTypes {
  release {
    debuggable false
    minifyEnabled true
    shrinkResources true
    proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
  }
}`,
      verifyCommand: './gradlew assembleRelease && ls -lh app/build/outputs/mapping/release/mapping.txt',
    },
    faqs: [
      {
        q: 'Will R8 break my Gson or Retrofit JSON models?',
        a: 'Only if model fields are renamed without @SerializedName annotations or keep rules. Annotate serialized fields with @SerializedName or add a -keep rule for your dto package.',
      },
    ],
  },
  {
    slug: 'owasp-masvs-v2-android-security-checklist',
    title: 'OWASP MASVS v2 Android Security Checklist Before Play Store Release',
    metaTitle: 'OWASP MASVS v2 Android Security Checklist (2026) | CheckMyAPK',
    metaDescription:
      'Complete pre-launch Android APK security checklist mapped to OWASP MASVS v2 covering storage, crypto, network TLS, IPC platform guards, and binary resilience.',
    category: 'Play Store Compliance',
    owaspRef: 'MASVS-V2',
    publishedAt: '2026-11-08',
    readTime: '8 min read',
    keywords: [
      'owasp masvs v2 checklist',
      'android security checklist',
      'play store security audit',
      'mobile app pentest checklist',
    ],
    excerpt:
      'A practical, engineering-ready pre-release checklist aligned to OWASP MASVS v2 so your Android release passes security reviews and enterprise vendor audits cleanly.',
    summaryPoints: [
      'MASVS-STORAGE & CRYPTO: Disable allowBackup, eliminate hardcoded secrets, and use AES-GCM + AndroidKeyStore.',
      'MASVS-NETWORK: Enforce HTTPS-only cleartext=false, reject user CAs in release, and pin critical API certificates.',
      'MASVS-PLATFORM & RESILIENCE: Lock down exported IPC components, enable R8 obfuscation, and verify release keystore signing.',
    ],
    sections: [
      {
        heading: '1. Storage & Cryptography (MASVS-STORAGE / MASVS-CRYPTO)',
        body: [
          'Ensure no authentication tokens, SQLite databases, or secrets leak through backups or weak ciphers.',
        ],
        bullets: [
          'Set android:allowBackup="false" and configure dataExtractionRules for Android 12+.',
          'Never use AES/ECB, DES, MD5, or hardcoded SecretKeySpec / static IVs.',
          'Store sensitive tokens in EncryptedSharedPreferences backed by AndroidKeyStore.',
        ],
      },
      {
        heading: '2. Network & TLS Transport (MASVS-NETWORK)',
        body: [
          'All production API communication must be strictly encrypted and validated against trusted CAs.',
        ],
        bullets: [
          'Enforce android:usesCleartextTraffic="false" and remove hardcoded http:// endpoints.',
          'Never ship empty X509TrustManager, TrustAllHostnameVerifier, or WebView SslErrorHandler.proceed().',
          'Add SPKI Certificate Pinning for banking, auth, or sensitive enterprise APIs.',
        ],
      },
      {
        heading: '3. Platform IPC & Binary Resilience (MASVS-PLATFORM / MASVS-RESILIENCE)',
        body: [
          'Minimize attack surface exposed to other apps on the device and raise the bar against tampering.',
        ],
        bullets: [
          'Verify android:debuggable="false" and release keystore v2/v3 signing.',
          'Audit all exported Activities, Services, Receivers, and Providers.',
          'Enable R8 obfuscation and ensure native .so libraries compile with PIE, NX, Stack Canary, and RELRO.',
        ],
      },
    ],
    codeDiff: {
      filename: 'res/xml/data_extraction_rules.xml & AndroidManifest.xml',
      language: 'xml',
      before: `<application
    android:debuggable="true"
    android:allowBackup="true"
    android:usesCleartextTraffic="true" />`,
      after: `<application
    android:debuggable="false"
    android:allowBackup="false"
    android:fullBackupContent="false"
    android:dataExtractionRules="@xml/data_extraction_rules"
    android:usesCleartextTraffic="false"
    android:networkSecurityConfig="@xml/network_security_config" />`,
      verifyCommand: 'Upload signed release .apk to CheckMyAPK.com -> Target Grade A / A+ (85-100)',
    },
    faqs: [
      {
        q: 'How long does an automated OWASP MASVS static audit take?',
        a: 'Automated static manifest, Dalvik DEX CFG, and Native ELF verification takes 5 to 15 seconds on CheckMyAPK and catches 80%+ of common pre-release misconfigurations.',
      },
    ],
  },
  {
    slug: 'ssl-certificate-pinning-android-okhttp-guide',
    title: 'Android SSL/TLS Certificate Pinning with OkHttp & network_security_config.xml',
    metaTitle: 'Android SSL Certificate Pinning Guide (OkHttp & XML) | CheckMyAPK',
    metaDescription:
      'Stop Burp Suite, Charles Proxy, and rogue CA interception in Android apps using SPKI SHA-256 certificate pinning with backup pins.',
    category: 'Android APK',
    owaspRef: 'MASVS-NETWORK-2',
    publishedAt: '2026-11-05',
    readTime: '6 min read',
    keywords: [
      'android ssl certificate pinning',
      'okhttp certificatepinner',
      'network_security_config pin-set',
      'prevent mitm android',
    ],
    excerpt:
      'HTTPS alone trusts over 100 root Certificate Authorities. Pinning your API public key (SPKI) guarantees your Android app talks exclusively to your real backend.',
    summaryPoints: [
      'Always pin the Subject Public Key Info (SPKI) SHA-256 hash—not the leaf certificate—so routine cert renewals do not break your app.',
      'Always include at least one backup pin (intermediate CA or standby key pair) to prevent app lockouts during emergency key rotation.',
      'Declarative XML pinning in network_security_config.xml works across OkHttp, Retrofit, and WebViews simultaneously.',
    ],
    sections: [
      {
        heading: 'Why Standard HTTPS Is Not Enough for Sensitive Apps',
        body: [
          'If a user installs a corporate proxy certificate or falls victim to a compromised CA or Frida/Burp proxy on a rooted device, standard TLS validation accepts the attacker certificate. Certificate pinning restricts the trusted key set to hashes you explicitly control.',
        ],
      },
      {
        heading: 'Extracting Your SPKI SHA-256 Pin Safely',
        body: [
          'Use OpenSSL against your production API domain to compute the Base64-encoded SHA-256 digest of the public key, plus a second backup pin for your certificate authority or rotation key.',
        ],
      },
    ],
    codeDiff: {
      filename: 'res/xml/network_security_config.xml',
      language: 'xml',
      before: `<!-- No pin-set configured: trusts any system or compromised CA -->
<network-security-config>
  <base-config cleartextTrafficPermitted="false" />
</network-security-config>`,
      after: `<network-security-config>
  <domain-config cleartextTrafficPermitted="false">
    <domain includeSubdomains="true">api.yourdomain.com</domain>
    <pin-set expiration="2028-01-01">
      <pin digest="SHA-256">PRIMARY_SPKI_BASE64_SHA256_HASH=</pin>
      <pin digest="SHA-256">BACKUP_SPKI_BASE64_SHA256_HASH=</pin>
    </pin-set>
  </domain-config>
</network-security-config>`,
      verifyCommand:
        'openssl s_client -servername api.yourdomain.com -connect api.yourdomain.com:443 </dev/null 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64',
    },
    faqs: [
      {
        q: 'What happens when a pin-set expiration date passes?',
        a: 'Android falls back to standard system CA validation after the expiration date so older un-updated app installs do not permanently lose network connectivity.',
      },
    ],
  },
  {
    slug: 'android-native-elf-hardening-pie-nx-relro',
    title: 'Native .so ELF Binary Hardening in Android NDK: PIE, NX, Stack Canary & RELRO',
    metaTitle: 'Android Native .so ELF Hardening (PIE, NX, Canary, RELRO) | CheckMyAPK',
    metaDescription:
      'Harden C/C++ shared libraries (.so) in your Android APK against memory corruption exploits by enabling PIE, NX stack, Stack Canary, and Full RELRO in CMake.',
    category: 'Android APK',
    owaspRef: 'MASVS-CODE-3',
    publishedAt: '2026-11-02',
    readTime: '6 min read',
    keywords: [
      'android elf binary hardening',
      'so library pie nx relro',
      'android ndk security flags',
      'stack canary cmake android',
    ],
    excerpt:
      'Compiled C/C++ libraries inside lib/arm64-v8a/*.so bypass JVM memory safety. Missing PIE, NX, Stack Canary, or RELRO flags turn memory bugs into remote code execution.',
    summaryPoints: [
      'PIE (Position Independent Executable) enables ASLR so attackers cannot predict memory addresses.',
      'NX (No-Execute) prevents shellcode execution on the stack, while Stack Canaries detect buffer overflows before return.',
      'Full RELRO (-Wl,-z,relro,-z,now) marks the Global Offset Table read-only to block GOT overwrite attacks.',
    ],
    sections: [
      {
        heading: 'Why Native .so Libraries Need Binary Audit Checks',
        body: [
          'Even if your app is written in Kotlin or Flutter, native C/C++ plugins for image processing, audio, encryption, or game engines ship compiled ELF (.so) binaries inside the APK. Legacy NDK toolchains or custom CMake flags frequently omit Stack Canary or Full RELRO.',
        ],
      },
      {
        heading: 'Enforcing Hardening Flags in CMakeLists.txt',
        body: [
          'Add compiler and linker flags directly to your NDK CMakeLists.txt so every arm64-v8a and armeabi-v7a shared object ships with modern exploit mitigations enabled.',
        ],
      },
    ],
    codeDiff: {
      filename: 'app/src/main/cpp/CMakeLists.txt',
      language: 'cmake',
      before: `# Default CMake build without explicit hardening flags
add_library(native-lib SHARED native-lib.cpp)`,
      after: `# Enforce Stack Canary, PIE, FORTIFY_SOURCE, NX Stack & Full RELRO
set(CMAKE_C_FLAGS "\${CMAKE_C_FLAGS} -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2")
set(CMAKE_CXX_FLAGS "\${CMAKE_CXX_FLAGS} -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2")
set(CMAKE_SHARED_LINKER_FLAGS "\${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,noexecstack -Wl,-z,relro,-z,now")
add_library(native-lib SHARED native-lib.cpp)`,
      verifyCommand: 'readelf -l -d app/build/intermediates/cmake/release/obj/arm64-v8a/libnative-lib.so',
    },
    faqs: [
      {
        q: 'Do these hardening flags slow down native C++ performance?',
        a: 'The overhead of -fstack-protector-strong and Full RELRO is negligible (typically under 1%) while blocking entire classes of memory corruption exploits.',
      },
    ],
  },
];
