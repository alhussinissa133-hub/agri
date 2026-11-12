// ينسخ مكتبتي QR (رسم + مسح) من node_modules إلى src/lib. إن غابتا يعمل التطبيق بالرمز النصي فقط.
const fs = require("fs"), path = require("path");
const root = path.join(__dirname, ".."), lib = path.join(root, "src", "lib"); fs.mkdirSync(lib, { recursive: true });
const items = [["qrcode-generator/qrcode.js", "qrcode.js"], ["jsqr/dist/jsQR.js", "jsQR.js"]];
for (const [from, to] of items) {
  const f = path.join(root, "node_modules", from);
  if (fs.existsSync(f)) { fs.copyFileSync(f, path.join(lib, to)); console.log("lib ok:", to); } else console.warn("تحذير: لم أجد " + from + " (شغّل npm install). ميزة QR لن تعمل.");
}
