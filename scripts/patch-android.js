// بعد `npx cap add android`: إذن الكاميرا + أيقونة التطبيق + اتجاه الشاشة
const fs = require("fs"), path = require("path");
const root = path.join(__dirname, ".."), and = path.join(root, "android");
if (!fs.existsSync(and)) { console.error("مجلد android غير موجود"); process.exit(1); }
const mf = path.join(and, "app", "src", "main", "AndroidManifest.xml"); let x = fs.readFileSync(mf, "utf8");
if (!x.includes("android.permission.CAMERA")) {
  x = x.replace(/<uses-permission android:name="android.permission.INTERNET"\s*\/>/, m => m + '\n    <uses-permission android:name="android.permission.CAMERA" />\n    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />\n    <uses-feature android:name="android.hardware.camera" android:required="false" />');
  if (!x.includes("android.permission.CAMERA")) x = x.replace("</manifest>", '    <uses-permission android:name="android.permission.CAMERA" />\n    <uses-feature android:name="android.hardware.camera" android:required="false" />\n</manifest>');
}
if (!x.includes("usesCleartextTraffic")) x = x.replace("<application", '<application android:usesCleartextTraffic="true"');
fs.writeFileSync(mf, x);
const res = path.join(and, "app", "src", "main", "res");
fs.rmSync(path.join(res, "mipmap-anydpi-v26"), { recursive: true, force: true });       // نستخدم أيقوناتنا PNG بدل الأيقونة المتكيفة الافتراضية
const srcIcons = path.join(root, "assets", "android");
for (const d of fs.readdirSync(srcIcons)) {
  const to = path.join(res, d); fs.mkdirSync(to, { recursive: true });
  for (const f of fs.readdirSync(path.join(srcIcons, d))) fs.copyFileSync(path.join(srcIcons, d, f), path.join(to, f));
}
console.log("android patched");
