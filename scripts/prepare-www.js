// يجهّز مجلد www لتطبيق الأندرويد من src
const fs = require("fs"), path = require("path");
require("./prepare-libs.js");
const root = path.join(__dirname, ".."), src = path.join(root, "src"), www = path.join(root, "www");
fs.rmSync(www, { recursive: true, force: true });
fs.cpSync(src, www, { recursive: true });
console.log("www جاهز:", fs.readdirSync(www).join(", "));
